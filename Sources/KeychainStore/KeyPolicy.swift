// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// KeyPolicy.swift — per-fingerprint policy for cached passphrase entries.
//
// Tier 2 introduces three knobs the user can set per GPG key:
//
//   biometry      Touch ID / passcode flag combination passed to
//                 SecAccessControlCreateWithFlags. Picks the ACL strictness.
//   accessibility kSecAttrAccessible*ThisDeviceOnly variant. Whether the
//                 entry survives a login-password removal, etc.
//   cacheTTL      Soft expiry. nil = forever. Tier 4 enforces; Tier 2 stores.
//
// Persistence is one JSON blob per record (default + each fingerprint) in
// our UserDefaults suite, keyed by `KeyPolicies` (default) and
// `KeyPolicies/<fingerprint>` (per-key). JSON is straightforward to inspect
// in `defaults read` for diagnosis without exposing any secret material.

import Foundation
import Security

// MARK: - KeyPolicy

/// Per-fingerprint policy for a cached passphrase entry.
public struct KeyPolicy: Codable, Equatable, Sendable {

    /// Biometric / passcode requirement applied to the entry's
    /// `SecAccessControl`.
    public enum BiometryRequirement: String, Codable, CaseIterable, Sendable {
        /// `.userPresence` — Touch ID OR device passcode. The legacy
        /// default. Loosest gate; survives biometry enrollment changes.
        case userPresence
        /// `.biometryCurrentSet` — biometry only, invalidated on any
        /// enrollment change. The "security-tool" posture: a stolen
        /// fingerprint added after first save cannot unlock the entry.
        case biometryCurrentSet
        /// `.biometryAny` — biometry only, survives enrollment changes.
        /// The "shared-machine" posture: the entry continues to work after
        /// a new authorized user enrolls.
        case biometryAny
        /// `.devicePasscode` — passcode only, no biometry. For users who
        /// disabled Touch ID or whose Mac lacks the sensor.
        case devicePasscode
    }

    /// Keychain accessibility constant. Always `ThisDeviceOnly` (never
    /// sync via iCloud) — the variant choice controls whether the entry
    /// survives removal of the login password.
    public enum Accessibility: String, Codable, CaseIterable, Sendable {
        /// `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`. Standard
        /// keychain unlock semantics. The current default.
        case whenUnlocked
        /// `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`. The entry
        /// is wiped if the user removes their login password. Higher
        /// assurance, less convenient.
        case whenPasscodeSet
    }

    public var biometry: BiometryRequirement
    public var accessibility: Accessibility
    /// Soft expiry in seconds. nil = never expire. Tier 4 honours; Tier 2
    /// stores. Negative values are coerced to nil on decode.
    public var cacheTTLSeconds: Int?

    public init(
        biometry: BiometryRequirement = .userPresence,
        accessibility: Accessibility = .whenUnlocked,
        cacheTTLSeconds: Int? = nil
    ) {
        self.biometry = biometry
        self.accessibility = accessibility
        self.cacheTTLSeconds = (cacheTTLSeconds ?? 0) > 0 ? cacheTTLSeconds : nil
    }

    /// Backward-compatible default. Matches the pre-Tier-2 KeychainStore
    /// behaviour exactly: `.userPresence` + `whenUnlockedThisDeviceOnly`,
    /// no expiry.
    public static let legacyDefault = KeyPolicy(
        biometry: .userPresence,
        accessibility: .whenUnlocked,
        cacheTTLSeconds: nil
    )

    // MARK: Security mapping

    /// Map the policy onto the Security framework arguments used by
    /// `SecAccessControlCreateWithFlags`. The accessibility constant is
    /// `CFTypeRef` because the constants are imported as untyped CF.
    public var secAccessibility: CFTypeRef {
        switch accessibility {
        case .whenUnlocked:
            return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        case .whenPasscodeSet:
            return kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        }
    }

    public var secAccessControlFlags: SecAccessControlCreateFlags {
        switch biometry {
        case .userPresence:
            return [.userPresence]
        case .biometryCurrentSet:
            return [.biometryCurrentSet]
        case .biometryAny:
            return [.biometryAny]
        case .devicePasscode:
            return [.devicePasscode]
        }
    }
}

// MARK: - KeyPolicyStore

/// Persistence for per-key policy. Reads and writes JSON blobs in a
/// UserDefaults suite. Independent of `UserPrefs` to keep the master
/// "keychain enabled" toggle separate from per-key tuning.
///
/// Conventions:
///   - `KeyPolicies/default`              → JSON of `KeyPolicy`
///   - `KeyPolicies/<fingerprint-lower>` → JSON of `KeyPolicy`
///
/// Fingerprints are normalised to lowercase on lookup so case-insensitive
/// hex comparisons round-trip even if the caller mixes cases.
///
/// `@unchecked Sendable`: `UserDefaults` is documented thread-safe but
/// not formally Sendable; matches the pattern in `UserPrefs`.
public struct KeyPolicyStore: @unchecked Sendable {

    private static let defaultKeyName = "KeyPolicies/default"
    private static let perKeyPrefix = "KeyPolicies/"

    private let defaults: UserDefaults

    public init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    // MARK: Default policy

    /// The policy applied to new "Save in Keychain" entries when the
    /// fingerprint has no per-key override. Falls back to
    /// `KeyPolicy.legacyDefault` if the store is empty or the stored
    /// blob fails to decode.
    public var defaultPolicy: KeyPolicy {
        guard let raw = defaults.data(forKey: Self.defaultKeyName) else {
            return .legacyDefault
        }
        return Self.decode(raw) ?? .legacyDefault
    }

    public func setDefaultPolicy(_ policy: KeyPolicy) {
        guard let raw = Self.encode(policy) else { return }
        defaults.set(raw, forKey: Self.defaultKeyName)
    }

    // MARK: Per-key policy

    /// Effective policy for `fingerprint`. Per-key override if set,
    /// otherwise the stored default, otherwise `KeyPolicy.legacyDefault`.
    public func policy(for fingerprint: String) -> KeyPolicy {
        let key = Self.key(for: fingerprint)
        if let raw = defaults.data(forKey: key),
           let decoded = Self.decode(raw)
        {
            return decoded
        }
        return defaultPolicy
    }

    /// Per-key override only — does not fall back to the default. Returns
    /// nil if there is no override. Useful for the Settings pane so it
    /// can show which rows have an explicit override vs. follow the
    /// default.
    public func override(for fingerprint: String) -> KeyPolicy? {
        let key = Self.key(for: fingerprint)
        guard let raw = defaults.data(forKey: key) else { return nil }
        return Self.decode(raw)
    }

    public func setPolicy(_ policy: KeyPolicy, for fingerprint: String) {
        guard let raw = Self.encode(policy) else { return }
        defaults.set(raw, forKey: Self.key(for: fingerprint))
    }

    /// Remove a per-key override so the fingerprint reverts to the
    /// default. Idempotent.
    public func removeOverride(for fingerprint: String) {
        defaults.removeObject(forKey: Self.key(for: fingerprint))
    }

    /// All fingerprints with an explicit override, sorted lexically.
    public func overriddenFingerprints() -> [String] {
        let all = defaults.dictionaryRepresentation()
        return all.keys
            .filter { $0.hasPrefix(Self.perKeyPrefix) && $0 != Self.defaultKeyName }
            .map { String($0.dropFirst(Self.perKeyPrefix.count)) }
            .sorted()
    }

    // MARK: Internals

    private static func key(for fingerprint: String) -> String {
        perKeyPrefix + fingerprint.lowercased()
    }

    private static func encode(_ policy: KeyPolicy) -> Data? {
        try? JSONEncoder().encode(policy)
    }

    private static func decode(_ raw: Data) -> KeyPolicy? {
        try? JSONDecoder().decode(KeyPolicy.self, from: raw)
    }
}

// MARK: - Keychain enumeration

/// Read-only enumeration helper: lists fingerprints that currently have a
/// cached entry in the data-protection keychain under our service name.
/// Returns only attributes (no `kSecValueData`) so no biometric prompt
/// fires. Used by the per-key Settings pane to populate its rows.
public enum KeychainEnumerator {

    /// Enumerate `kSecAttrAccount` values for stored entries.
    ///
    /// - Parameters:
    ///   - service: keychain service name. Use `"GnuPG"` for production.
    ///   - useDataProtectionKeychain: true for the modern backend (production).
    ///
    /// Returns an empty array on any non-success / non-not-found status —
    /// the Settings pane treats "couldn't enumerate" as "no rows" rather
    /// than surfacing a hard error.
    public static func fingerprints(
        service: String = "GnuPG",
        useDataProtectionKeychain: Bool = true
    ) -> [String] {
        var query: [String: Any] = [
            kSecClass as String:              kSecClassGenericPassword,
            kSecAttrService as String:        service,
            kSecMatchLimit as String:         kSecMatchLimitAll,
            kSecReturnAttributes as String:   kCFBooleanTrue as Any,
            // Critical: do NOT request kSecReturnData — that would trigger
            // a biometric prompt per entry on a `.userPresence`-guarded
            // store. We only need account values for the list.
            kSecUseAuthenticationUI as String: kSecUseAuthenticationUISkip,
        ]
        if useDataProtectionKeychain {
            query[kSecUseDataProtectionKeychain as String] = kCFBooleanTrue as Any
        }

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let array = result as? [[String: Any]] else {
            return []
        }
        return array
            .compactMap { $0[kSecAttrAccount as String] as? String }
            .sorted()
    }
}

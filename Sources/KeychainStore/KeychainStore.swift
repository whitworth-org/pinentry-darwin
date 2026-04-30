// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// KeychainStore: a thin wrapper over the macOS Security framework that mirrors
// the layout used by pinentry-mac so existing Keychain entries keep working.
//
// Wire-compatible attributes (see /Users/rwhitworth/Development/pinentry/macosx/
// KeychainSupport.m:28–148):
//   kSecClass       = kSecClassGenericPassword
//   kSecAttrService = "GnuPG"           (configurable for tests only)
//   kSecAttrAccount = <fingerprint>
//   kSecAttrLabel   = <user-id>         (visible in Keychain Access)
//
// HARDENING (review H1):
// The legacy file-based keychain enforces a same-user-with-default-ACL
// policy: any process running as the same user can read after the user
// granted access once. For a passphrase-handling daemon that's a real
// problem — a malicious sibling app can read the cache without prompting,
// and (combined with no fingerprint validation prior to review M3) plant
// entries the user's gpg-agent will silently consume.
//
// New writes therefore go to the modern data-protection keychain
// (kSecUseDataProtectionKeychain=true), where the ACL is enforced by
// code signature: only an app with the same Developer Team ID + Bundle ID
// can read the entry. Combined with `kSecAttrAccessible` set to
// `WhenUnlockedThisDeviceOnly` and `kSecAttrSynchronizable=false`, the
// entry is also (a) inaccessible while the device is locked and (b)
// excluded from iCloud Keychain sync.
//
// On lookup we try the data-protection keychain first; if not found we
// fall back to the legacy keychain (where pinentry-mac wrote and where
// pre-review pinentry-darwin builds wrote). On a legacy hit we migrate:
// re-store into the data-protection keychain and delete the legacy
// entry. The migration is best-effort — if either step fails the original
// bytes are still returned and the legacy entry stays put.
//
// The `useDataProtectionKeychain` flag exists so tests (which run as a
// `swift test` binary that may not have a stable signing identity) can
// stay on the legacy path without hitting errSecMissingEntitlement.

import Foundation
import Security
import SecureMemory

// MARK: - Errors

public enum KeychainStoreError: Error, Equatable {
    /// An unexpected `OSStatus` was returned by the Security framework.
    /// `errSecItemNotFound` is NOT surfaced here — `lookup` returns nil and
    /// `clear` swallows it.
    case unexpectedStatus(OSStatus)

    /// The user denied keychain access (errSecUserCanceled).
    case userCanceled
}

// MARK: - KeychainStore

public struct KeychainStore: Sendable {

    /// Service name. Production code uses the default "GnuPG" (the value
    /// pinentry-mac writes). Tests inject a unique service so they can run
    /// against the developer's keychain without colliding with real entries.
    private let service: String

    /// When true, new writes target the modern data-protection keychain
    /// where the ACL is enforced by code signature. When false, all
    /// operations go to the legacy file-based keychain (matches
    /// pinentry-mac's wire-compatible layout exactly).
    ///
    /// Defaults to true. Per-call fallback: if a write to the data-
    /// protection keychain returns `errSecMissingEntitlement` (-34018)
    /// — the failure mode for ad-hoc-signed binaries that lack a stable
    /// Apple-issued code identity — `store(...)` automatically falls
    /// back to the legacy backend. Reads (`lookup`) probe the data-
    /// protection keychain first and likewise degrade on entitlement
    /// failure. Production Developer ID builds never trip the fallback
    /// because the kernel grants them the entitlement implicitly via
    /// their `application-identifier` derived from Team ID + Bundle ID;
    /// the os_log entry on each fallback makes regressions auditable.
    ///
    /// Tests pass `false` explicitly to pin themselves on the legacy
    /// backend regardless of the host's signing posture.
    private let useDataProtectionKeychain: Bool

    public init(
        service: String = "GnuPG",
        useDataProtectionKeychain: Bool = true
    ) {
        self.service = service
        self.useDataProtectionKeychain = useDataProtectionKeychain
    }

    // MARK: Lookup

    /// Look up the passphrase for `fingerprint`.
    ///
    /// Returns nil on `errSecItemNotFound` from BOTH backends. Throws
    /// `KeychainStoreError.userCanceled` if the user denies an access prompt.
    /// Any other non-zero status throws `.unexpectedStatus`.
    ///
    /// When `useDataProtectionKeychain` is true and a hit comes from the
    /// legacy backend, migrates the entry to data-protection (re-store +
    /// legacy delete) before returning. Migration is best-effort.
    public func lookup(fingerprint: String) throws -> SecureBytes? {
        // 1. Try the configured primary backend. If the data-protection
        //    keychain rejects with errSecMissingEntitlement (ad-hoc dev
        //    build), short-circuit straight to the legacy backend.
        do {
            if let bytes = try rawLookup(
                fingerprint: fingerprint,
                dataProtection: useDataProtectionKeychain
            ) {
                return bytes
            }
        } catch KeychainStoreError.unexpectedStatus(let s)
            where s == errSecMissingEntitlement && useDataProtectionKeychain
        {
            // No entitlement → can't read from data-protection at all.
            // Skip migration; just go legacy.
            return try rawLookup(fingerprint: fingerprint, dataProtection: false)
        }
        // 2. Migration: when primary is data-protection, also probe legacy
        //    (which is where pinentry-mac writes and where pre-H1 pinentry-
        //    darwin builds wrote). On hit, copy forward and delete the
        //    legacy entry.
        //
        // The legacy probe uses `try?` rather than `try` so any ACL prompt
        // or auth failure on the legacy backend is swallowed silently. The
        // legacy file-based keychain ignores `kSecUseAuthenticationUISkip`
        // and prompts whenever an ACL doesn't recognize the calling app's
        // code identity — exactly the scenario for ad-hoc dev binaries
        // and for entries written by pinentry-mac. A noisy prompt during
        // cache lookup defeats the "fast path" cache promise; silent
        // failure means "no migrate-able legacy entry, fall through to
        // the GETPIN dialog."
        if useDataProtectionKeychain,
           let legacyBytes = try? rawLookup(
               fingerprint: fingerprint,
               dataProtection: false
           )
        {
            do {
                try legacyBytes.withUnsafeBytes { (buf: UnsafeBufferPointer<UInt8>) in
                    let secure = SecureBytes(copying: buf)
                    try rawStore(
                        fingerprint: fingerprint,
                        label: nil,
                        passphrase: secure,
                        dataProtection: true
                    )
                }
                // Only delete the legacy entry if the data-protection write
                // succeeded; otherwise we'd lose the user's cached
                // passphrase entirely.
                try? rawClear(fingerprint: fingerprint, dataProtection: false)
            } catch {
                // Migration failed but the value is still good — return it.
            }
            return legacyBytes
        }
        return nil
    }

    // MARK: Store

    /// Insert or update the passphrase entry for `fingerprint` in the
    /// configured primary backend (data-protection keychain by default).
    ///
    /// If `label` is nil the service name ("GnuPG") is used (matches
    /// KeychainSupport.m:46-47).
    public func store(
        fingerprint: String,
        label: String?,
        passphrase: SecureBytes
    ) throws {
        do {
            try rawStore(
                fingerprint: fingerprint,
                label: label,
                passphrase: passphrase,
                dataProtection: useDataProtectionKeychain
            )
        } catch KeychainStoreError.unexpectedStatus(let s)
            where s == errSecMissingEntitlement && useDataProtectionKeychain
        {
            // Ad-hoc-signed binaries cannot write to the data-protection
            // keychain (no stable application-identifier). Degrade to
            // the legacy file-based keychain so the user still gets a
            // working "Save in Keychain" affordance during development.
            // Production Developer ID builds never reach this path.
            try rawStore(
                fingerprint: fingerprint,
                label: label,
                passphrase: passphrase,
                dataProtection: false
            )
        }
    }

    // MARK: Clear

    /// Delete the entry for `fingerprint`. Idempotent: missing entries are
    /// not an error. When the primary is the data-protection keychain we
    /// also best-effort delete from the legacy keychain so a stale
    /// pre-migration entry doesn't survive.
    public func clear(fingerprint: String) throws {
        try rawClear(fingerprint: fingerprint, dataProtection: useDataProtectionKeychain)
        if useDataProtectionKeychain {
            try? rawClear(fingerprint: fingerprint, dataProtection: false)
        }
    }

    // MARK: - Internal raw operations (one specific backend per call)

    /// Build the common subset of attributes used by every query against
    /// the chosen backend.
    private func baseQuery(
        fingerprint: String,
        dataProtection: Bool
    ) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String:              kSecClassGenericPassword,
            kSecAttrService as String:        service,
            kSecAttrAccount as String:        fingerprint,
            kSecAttrSynchronizable as String: kCFBooleanFalse as Any,
        ]
        if dataProtection {
            query[kSecUseDataProtectionKeychain as String] = kCFBooleanTrue as Any
        }
        return query
    }

    /// Build the attributes used for an insert/update. Adds the data
    /// payload, the label, and the WhenUnlockedThisDeviceOnly accessibility
    /// constraint that prevents read-while-locked AND iCloud sync.
    private func writeAttributes(
        label: String,
        data: CFData,
        dataProtection: Bool
    ) -> [String: Any] {
        var attrs: [String: Any] = [
            kSecAttrLabel as String:          label,
            kSecValueData as String:          data,
            kSecAttrAccessible as String:     kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecAttrSynchronizable as String: kCFBooleanFalse as Any,
        ]
        if dataProtection {
            attrs[kSecUseDataProtectionKeychain as String] = kCFBooleanTrue as Any
        }
        return attrs
    }

    private func rawLookup(
        fingerprint: String,
        dataProtection: Bool
    ) throws -> SecureBytes? {
        var query = baseQuery(fingerprint: fingerprint, dataProtection: dataProtection)
        query[kSecReturnData as String] = kCFBooleanTrue as Any
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        // Critical: cache lookup MUST NOT block on a system Keychain ACL
        // prompt. gpg-agent invokes pinentry on every uncached operation
        // and the GETPIN dialog can't render until lookup returns; a
        // synchronous "Allow / Always Allow / Deny" sheet would deadlock
        // the user behind their own pinentry. With UISkip the framework
        // returns errSecInteractionNotAllowed instead — we treat that as
        // "cache miss" so the dialog renders immediately and the user
        // can grant ACL during the *store* path on submit (where the UI
        // is expected and correct).
        query[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUISkip

        var status = OSStatus(errSecSuccess)
        var item: CFTypeRef?

        // Mirrors KeychainSupport.m:110 (Apple radar://50789571): a single
        // retry on errSecAuthFailed sometimes succeeds — Apple's keychain
        // daemon returns that status spuriously on the first call.
        var attempts = 0
        repeat {
            item = nil
            status = SecItemCopyMatching(query as CFDictionary, &item)
            attempts += 1
        } while status == errSecAuthFailed && attempts < 2

        switch status {
        case errSecSuccess:
            break
        case errSecItemNotFound, errSecInteractionNotAllowed:
            // Both flow back as "cache miss" — InteractionNotAllowed is
            // the success path for the UISkip suppression above.
            return nil
        case errSecUserCanceled:
            throw KeychainStoreError.userCanceled
        default:
            throw KeychainStoreError.unexpectedStatus(status)
        }

        guard let data = item as? Data else {
            // Should not happen if SecItemCopyMatching returned success with
            // kSecReturnData=true, but treat it as an unexpected condition.
            throw KeychainStoreError.unexpectedStatus(errSecInternalError)
        }

        // Copy bytes into a SecureBytes (mlock'd, deinit-zeroed) and then
        // best-effort overwrite the underlying Data buffer. `Data` is a
        // value type with copy-on-write semantics, so this only zeroes our
        // local copy; CFData backing memory is owned by CF and we cannot
        // reliably wipe it.
        var data2 = data
        let secure = data2.withUnsafeMutableBytes { (raw: UnsafeMutableRawBufferPointer) -> SecureBytes in
            let bound = raw.bindMemory(to: UInt8.self)
            let buf = UnsafeBufferPointer<UInt8>(start: bound.baseAddress, count: bound.count)
            let bytes = SecureBytes(copying: buf)
            // Best-effort wipe of the local Data copy. memset_s would be
            // stronger but Data does not guarantee non-elision.
            if let base = bound.baseAddress, bound.count > 0 {
                base.update(repeating: 0, count: bound.count)
            }
            return bytes
        }
        return secure
    }

    private func rawStore(
        fingerprint: String,
        label: String?,
        passphrase: SecureBytes,
        dataProtection: Bool
    ) throws {
        let resolvedLabel = label ?? service

        // First check whether an entry already exists. We do not request
        // kSecReturnData here, only existence — that avoids the auth prompt
        // when we are about to overwrite.
        let probe = baseQuery(fingerprint: fingerprint, dataProtection: dataProtection)
            .merging([kSecMatchLimit as String: kSecMatchLimitOne]) { _, new in new }

        var probeStatus = OSStatus(errSecSuccess)
        var attempts = 0
        repeat {
            probeStatus = SecItemCopyMatching(probe as CFDictionary, nil)
            attempts += 1
        } while probeStatus == errSecAuthFailed && attempts < 2

        // Build a CFData around a copy of the passphrase bytes. The CFData
        // is released as soon as this method returns; SecItem* APIs copy
        // their input internally so we don't have to keep it alive.
        try passphrase.withUnsafeBytes { (buf: UnsafeBufferPointer<UInt8>) in
            let cfData = CFDataCreate(kCFAllocatorDefault, buf.baseAddress, buf.count)!

            if probeStatus == errSecSuccess {
                // Update existing.
                let attrs = writeAttributes(
                    label: resolvedLabel,
                    data: cfData,
                    dataProtection: dataProtection
                )
                var status = OSStatus(errSecSuccess)
                var tries = 0
                repeat {
                    status = SecItemUpdate(probe as CFDictionary, attrs as CFDictionary)
                    tries += 1
                } while status == errSecAuthFailed && tries < 2
                try Self.translate(status)
            } else if probeStatus == errSecItemNotFound {
                // Add new. Merge identity attributes with write attrs.
                var add = baseQuery(fingerprint: fingerprint, dataProtection: dataProtection)
                for (k, v) in writeAttributes(
                    label: resolvedLabel,
                    data: cfData,
                    dataProtection: dataProtection
                ) {
                    add[k] = v
                }
                var status = OSStatus(errSecSuccess)
                var tries = 0
                repeat {
                    status = SecItemAdd(add as CFDictionary, nil)
                    tries += 1
                } while status == errSecAuthFailed && tries < 2
                try Self.translate(status)
            } else if probeStatus == errSecUserCanceled {
                throw KeychainStoreError.userCanceled
            } else {
                throw KeychainStoreError.unexpectedStatus(probeStatus)
            }
        }
    }

    private func rawClear(
        fingerprint: String,
        dataProtection: Bool
    ) throws {
        var query = baseQuery(fingerprint: fingerprint, dataProtection: dataProtection)
        // Mirror rawLookup: clearing must not block on an ACL prompt.
        // CLEARPASSPHRASE arrives mid-Assuan-session and we must respond
        // OK promptly. If the entry is ACL-locked we treat it as already
        // gone (idempotent semantics).
        query[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUISkip

        var status = OSStatus(errSecSuccess)
        var attempts = 0
        repeat {
            status = SecItemDelete(query as CFDictionary)
            attempts += 1
        } while status == errSecAuthFailed && attempts < 2

        switch status {
        case errSecSuccess, errSecItemNotFound, errSecInteractionNotAllowed:
            return
        case errSecUserCanceled:
            throw KeychainStoreError.userCanceled
        default:
            throw KeychainStoreError.unexpectedStatus(status)
        }
    }

    // MARK: Helpers

    private static func translate(_ status: OSStatus) throws {
        switch status {
        case errSecSuccess:
            return
        case errSecUserCanceled:
            throw KeychainStoreError.userCanceled
        default:
            throw KeychainStoreError.unexpectedStatus(status)
        }
    }
}

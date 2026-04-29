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

    public init(service: String = "GnuPG") {
        self.service = service
    }

    // MARK: Lookup

    /// Look up the passphrase for `fingerprint`.
    ///
    /// Returns nil on `errSecItemNotFound`. Throws `KeychainStoreError.userCanceled`
    /// if the user denies the access prompt. Any other non-zero status throws
    /// `.unexpectedStatus`.
    public func lookup(fingerprint: String) throws -> SecureBytes? {
        let query: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: fingerprint,
            kSecReturnData as String:  kCFBooleanTrue as Any,
            kSecMatchLimit as String:  kSecMatchLimitOne,
        ]

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
        case errSecItemNotFound:
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

    // MARK: Store

    /// Insert or update the passphrase entry for `fingerprint`.
    ///
    /// If `label` is nil the service name ("GnuPG") is used (matches
    /// KeychainSupport.m:46-47).
    public func store(fingerprint: String, label: String?, passphrase: SecureBytes) throws {
        let resolvedLabel = label ?? service

        // First check whether an entry already exists. We do not request
        // kSecReturnData here, only existence — that avoids the auth prompt
        // when we are about to overwrite.
        let probe: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: fingerprint,
            kSecMatchLimit as String:  kSecMatchLimitOne,
        ]

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
                let attrs: [String: Any] = [
                    kSecValueData as String: cfData,
                    kSecAttrLabel as String: resolvedLabel,
                ]
                var status = OSStatus(errSecSuccess)
                var tries = 0
                repeat {
                    status = SecItemUpdate(probe as CFDictionary, attrs as CFDictionary)
                    tries += 1
                } while status == errSecAuthFailed && tries < 2
                try Self.translate(status)
            } else if probeStatus == errSecItemNotFound {
                // Add new.
                let add: [String: Any] = [
                    kSecClass as String:       kSecClassGenericPassword,
                    kSecAttrService as String: service,
                    kSecAttrAccount as String: fingerprint,
                    kSecAttrLabel as String:   resolvedLabel,
                    kSecValueData as String:   cfData,
                ]
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

    // MARK: Clear

    /// Delete the entry for `fingerprint`. Idempotent: missing entries are
    /// not an error.
    public func clear(fingerprint: String) throws {
        let query: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: fingerprint,
        ]

        var status = OSStatus(errSecSuccess)
        var attempts = 0
        repeat {
            status = SecItemDelete(query as CFDictionary)
            attempts += 1
        } while status == errSecAuthFailed && attempts < 2

        switch status {
        case errSecSuccess, errSecItemNotFound:
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

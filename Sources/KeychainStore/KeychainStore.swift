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
// HARDENING (review H1 + KC-1 / KC-2 / SL-2 / SL-3 / FV-1):
// The legacy file-based keychain enforces a same-user-with-default-ACL
// policy: any process running as the same user can read after the user
// granted access once. For a passphrase-handling daemon that's a real
// problem — a malicious sibling app can read the cache without prompting,
// and (combined with no fingerprint validation prior to review M3) plant
// entries the user's gpg-agent will silently consume.
//
// New writes therefore go to the modern data-protection keychain
// (kSecUseDataProtectionKeychain=true) with TWO factors of protection:
//   1. Code-signature ACL — only an app with the same Team ID + Bundle ID
//      can read the entry (data-protection backend default).
//   2. .userPresence access-control flag — every read demands a fresh
//      Touch ID / device-passcode confirmation. Combined with (1) this is
//      the cardholder-presence guarantee the H1 review prescribed.
// Plus `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` (no read while
// locked, no iCloud sync) and `kSecAttrSynchronizable=false`.
//
// Lookup tries the data-protection keychain first; if the entry is missing
// we probe the legacy keychain (where pinentry-mac and pre-H1 builds wrote)
// and migrate on hit (re-store + legacy delete; best-effort).
//
// Ad-hoc-signed binaries (swift run, locally re-signed copies, third-party
// rebuilds) cannot establish a stable application-identifier and so
// data-protection writes return `errSecMissingEntitlement`. We DO NOT
// silently fall back — the H1 attack model (legacy ACL = any-same-user)
// would be fully restored if we did. Instead we throw
// `KeychainStoreError.degradedNoEntitlement`; the UI is responsible for
// surfacing the condition to the user (warning badge + log) before any
// "Save in Keychain" tick takes effect. Legacy-keychain reads (for
// pre-H1 migration) are still attempted on lookup; that path is read-only,
// and we log the degraded posture exactly once per process via
// `KeychainStore.degradedPostureObserved`.
//
// The `useDataProtectionKeychain` flag exists so tests (which run as a
// `swift test` binary that may not have a stable signing identity) can
// stay on the legacy path without hitting errSecMissingEntitlement.

import Foundation
import LocalAuthentication
import Security
import SecureMemory
import os

// MARK: - Logger

/// One-shot guard so the missing-entitlement degraded-posture log fires
/// at most once per process. After the first occurrence the application
/// posture (`degradedPostureObserved`) is the authoritative signal and
/// the UI surfaces it; further log spam adds no value.
private let entitlementLogFlag = OSAllocatedUnfairLock<Bool>(initialState: false)

private let keychainLogger = Logger(
    subsystem: "org.whitworth.pinentry-darwin",
    category: "keychain"
)

// MARK: - Errors

public enum KeychainStoreError: Error, Equatable {
    /// An unexpected `OSStatus` was returned by the Security framework.
    /// `errSecItemNotFound` is NOT surfaced here — `lookup` returns nil and
    /// `clear` swallows it.
    case unexpectedStatus(OSStatus)

    /// The user denied keychain access (errSecUserCanceled).
    case userCanceled

    /// The data-protection keychain rejected the operation with
    /// `errSecMissingEntitlement` (-34018). This is the failure mode for
    /// ad-hoc-signed binaries that lack a stable application-identifier.
    /// We throw rather than silently fall back to the weaker legacy
    /// backend (KC-2): the UI MUST surface this so the user understands
    /// that "Save in Keychain" is not available with the current
    /// signing posture.
    case degradedNoEntitlement

    /// Building the in-process AccessControl for a `.userPresence`-gated
    /// write failed (KC-1). Wraps the underlying `CFError` description for
    /// diagnostic logging.
    case accessControlFailed(String)
}

// MARK: - KeychainStore

public struct KeychainStore: Sendable {

    /// Process-wide flag set the first time the data-protection keychain
    /// rejects an operation with `errSecMissingEntitlement` (FV-1). The UI
    /// reads this to render a "running in degraded posture" badge so the
    /// user knows the ad-hoc binary cannot use the hardened keychain
    /// backend. Production Developer-ID builds never trip this.
    public static var degradedPostureObserved: Bool {
        entitlementLogFlag.withLock { $0 }
    }

    /// Service name. Production code uses the default "GnuPG" (the value
    /// pinentry-mac writes). Tests inject a unique service so they can run
    /// against the developer's keychain without colliding with real entries.
    private let service: String

    /// When true, new writes target the modern data-protection keychain
    /// with `.userPresence` AccessControl (KC-1). When false, all
    /// operations go to the legacy file-based keychain (matches
    /// pinentry-mac's wire-compatible layout exactly) and no AccessControl
    /// is applied.
    ///
    /// Tests pass `false` explicitly to pin themselves on the legacy
    /// backend regardless of the host's signing posture. Production code
    /// uses the default (true).
    private let useDataProtectionKeychain: Bool

    /// When true (the default for production), data-protection writes
    /// include `SecAccessControlCreateWithFlags(.userPresence)` so every
    /// read triggers a Touch ID / device-passcode prompt. Disable only for
    /// integration tests that need to round-trip without biometric
    /// hardware; the default is the secure choice.
    private let requireUserPresence: Bool

    public init(
        service: String = "GnuPG",
        useDataProtectionKeychain: Bool = true,
        requireUserPresence: Bool = true
    ) {
        self.service = service
        self.useDataProtectionKeychain = useDataProtectionKeychain
        self.requireUserPresence = requireUserPresence
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
    ///
    /// `context`: optional pre-configured `LAContext` carrying a
    /// `SETDESC`-derived `localizedReason`. When non-nil it is passed as
    /// `kSecUseAuthenticationContext` so the Touch ID sheet displays the
    /// caller-supplied reason instead of the system default. Reusing the
    /// same context across multiple Sec* calls within
    /// `touchIDAuthenticationAllowableReuseDuration` (10 s) avoids a
    /// second prompt for follow-up SE ECDH operations in Tier 3.
    public func lookup(
        fingerprint: String,
        context: LAContext? = nil
    ) throws -> SecureBytes? {
        // 1. Try the configured primary backend. If the data-protection
        //    keychain rejects with errSecMissingEntitlement (ad-hoc dev
        //    build), record the degraded posture (FV-1) and probe the
        //    legacy backend read-only — no fallback write.
        do {
            if let bytes = try rawLookup(
                fingerprint: fingerprint,
                dataProtection: useDataProtectionKeychain,
                context: context
            ) {
                return bytes
            }
        } catch KeychainStoreError.unexpectedStatus(let s)
            where s == errSecMissingEntitlement && useDataProtectionKeychain
        {
            recordDegradedPosture(operation: "lookup", status: s)
            // Read-only legacy probe. We do NOT migrate from the legacy
            // backend in this branch because migration would require a
            // data-protection write, which is exactly what we just learned
            // we cannot perform. Returning the legacy bytes lets the user
            // continue to use the cached passphrase even on an ad-hoc
            // build, while the UI's degraded-posture badge tells them
            // why "Save in Keychain" is unavailable for new entries.
            return try rawLookup(
                fingerprint: fingerprint,
                dataProtection: false,
                context: nil
            )
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
               dataProtection: false,
               context: nil
           )
        {
            do {
                try legacyBytes.withUnsafeBytes { (buf: UnsafeBufferPointer<UInt8>) in
                    let secure = SecureBytes(copying: buf)
                    try rawStore(
                        fingerprint: fingerprint,
                        label: nil,
                        passphrase: secure,
                        dataProtection: true,
                        policy: defaultPolicy
                    )
                }
                // Only delete the legacy entry if the data-protection write
                // succeeded; otherwise we'd lose the user's cached
                // passphrase entirely.
                try? rawClear(fingerprint: fingerprint, dataProtection: false)
            } catch KeychainStoreError.degradedNoEntitlement {
                // Migration from legacy needs a DP write; without
                // entitlement the legacy entry stays put. Posture log
                // already emitted by rawStore.
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
    ///
    /// `policy` chooses the ACL strictness applied via
    /// `SecAccessControlCreateWithFlags`. Pass nil to inherit
    /// `KeychainStore.defaultPolicy` (`.userPresence` +
    /// `whenUnlockedThisDeviceOnly`, matching legacy behaviour).
    ///
    /// Throws `KeychainStoreError.degradedNoEntitlement` when the
    /// data-protection backend rejects with `errSecMissingEntitlement`
    /// (ad-hoc-signed binary). The store DOES NOT silently fall back to
    /// the legacy backend (KC-2) — the caller MUST surface the condition.
    public func store(
        fingerprint: String,
        label: String?,
        passphrase: SecureBytes,
        policy: KeyPolicy? = nil
    ) throws {
        try rawStore(
            fingerprint: fingerprint,
            label: label,
            passphrase: passphrase,
            dataProtection: useDataProtectionKeychain,
            policy: policy ?? defaultPolicy
        )
    }

    /// Policy applied when the caller does not provide one. Always the
    /// legacy default so callers that have not adopted the policy API
    /// see byte-identical keychain entries to the pre-Tier-2 build.
    public var defaultPolicy: KeyPolicy { .legacyDefault }

    // MARK: Clear

    /// Delete the entry for `fingerprint`. Idempotent: missing entries are
    /// not an error. When the primary is the data-protection keychain we
    /// also best-effort delete from the legacy keychain so a stale
    /// pre-migration entry doesn't survive (KC-6: `try?` here means
    /// synchronizable / ACL-locked entries that decline the delete are
    /// tolerated; idempotent clear is the contract).
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

    /// Build the AccessControl object that gates data-protection reads on
    /// fresh user presence (KC-1). The access constant baked into the
    /// access-control object replaces the standalone kSecAttrAccessible —
    /// they cannot both be set. Returns nil if not requested.
    ///
    /// `policy` selects the biometry / accessibility combination. The
    /// store-wide `requireUserPresence` flag remains the master switch:
    /// false disables the ACL entirely (test path), true honours the
    /// per-call policy.
    private func makeAccessControl(policy: KeyPolicy) throws -> SecAccessControl? {
        guard requireUserPresence else { return nil }
        var error: Unmanaged<CFError>?
        guard let control = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            policy.secAccessibility,
            policy.secAccessControlFlags,
            &error
        ) else {
            let detail = error.map { String(describing: $0.takeRetainedValue()) }
                ?? "SecAccessControlCreateWithFlags returned nil"
            throw KeychainStoreError.accessControlFailed(detail)
        }
        return control
    }

    /// Build the attributes used for an insert/update. Adds the data
    /// payload, the label, and either the AccessControl object (data
    /// protection + .userPresence) OR the standalone kSecAttrAccessible
    /// constant (legacy / non-presence-gated path).
    private func writeAttributes(
        label: String,
        data: CFData,
        dataProtection: Bool,
        accessControl: SecAccessControl?,
        policy: KeyPolicy
    ) -> [String: Any] {
        var attrs: [String: Any] = [
            kSecAttrLabel as String:          label,
            kSecValueData as String:          data,
            kSecAttrSynchronizable as String: kCFBooleanFalse as Any,
        ]
        if dataProtection {
            attrs[kSecUseDataProtectionKeychain as String] = kCFBooleanTrue as Any
        }
        if let accessControl {
            // AccessControl bakes in the accessibility constant.
            attrs[kSecAttrAccessControl as String] = accessControl
        } else {
            attrs[kSecAttrAccessible as String] = policy.secAccessibility
        }
        return attrs
    }

    private func rawLookup(
        fingerprint: String,
        dataProtection: Bool,
        context: LAContext?
    ) throws -> SecureBytes? {
        var query = baseQuery(fingerprint: fingerprint, dataProtection: dataProtection)
        query[kSecReturnData as String] = kCFBooleanTrue as Any
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        // Critical: cache lookup MUST NOT silently block. With .userPresence
        // ACL on data-protection writes the system will present a Touch ID /
        // passcode sheet on read, which is the expected UX for a hardened
        // cache. We allow that prompt by not setting kSecUseAuthenticationUI
        // at all (the default is kSecUseAuthenticationUIAllow).
        //
        // When the caller supplies an `LAContext` we hand it in via
        // `kSecUseAuthenticationContext` so the Touch ID sheet displays
        // the SETDESC-derived `localizedReason` instead of the system
        // default. The system still owns the sheet; we only customize
        // its reason text.
        //
        // For the legacy migration probe, we DO request UISkip — the legacy
        // ACL prompt is the deadlock the original code path comment warned
        // about, and migration is opportunistic anyway.
        if !dataProtection {
            query[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUISkip
        } else if let context {
            query[kSecUseAuthenticationContext as String] = context
        }

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
            // the success path for the legacy UISkip suppression above.
            // For data-protection it would mean the .userPresence prompt
            // was declined or unavailable; treat as miss so the UI falls
            // through to GETPIN.
            return nil
        case errSecUserCanceled:
            throw KeychainStoreError.userCanceled
        default:
            throw KeychainStoreError.unexpectedStatus(status)
        }

        // SL-2: do NOT bridge through Swift `Data`. The Swift Data bridge
        // is copy-on-write over the CFData backing buffer; calling
        // `withUnsafeMutableBytes` triggers a COW allocation, so any
        // wipe through that view zeroes only the COW copy and never the
        // CFData backing the secret. Use the CFData APIs directly.
        guard let itemRef = item else {
            throw KeychainStoreError.unexpectedStatus(errSecInternalError)
        }
        guard CFGetTypeID(itemRef) == CFDataGetTypeID() else {
            throw KeychainStoreError.unexpectedStatus(errSecInternalError)
        }
        let cfData = itemRef as! CFData
        let length = CFDataGetLength(cfData)
        if length == 0 {
            // SL-8: a zero-length entry would crash SecureBytes(copying:)'s
            // precondition. Treat zero-length stored payloads as "no
            // useful cache" rather than panic. The store path itself
            // refuses zero-length passphrases, but a hostile or corrupted
            // pre-existing keychain entry could carry one.
            return nil
        }
        guard let bytesPtr = CFDataGetBytePtr(cfData) else {
            throw KeychainStoreError.unexpectedStatus(errSecInternalError)
        }
        let buf = UnsafeBufferPointer<UInt8>(start: bytesPtr, count: length)
        let secure = SecureBytes(copying: buf)
        // CFData ref is owned by `item` / `itemRef`; releasing it returns
        // the bytes to the CF allocator pool unwiped (a known macOS
        // keychain reality outside our control). The fact that we never
        // bridged to Swift Data means at least no COW copy persists.
        return secure
    }

    private func rawStore(
        fingerprint: String,
        label: String?,
        passphrase: SecureBytes,
        dataProtection: Bool,
        policy: KeyPolicy
    ) throws {
        let resolvedLabel = label ?? service

        // First check whether an entry already exists. We do not request
        // kSecReturnData here, only existence — that avoids the auth prompt
        // when we are about to overwrite.
        var probe = baseQuery(fingerprint: fingerprint, dataProtection: dataProtection)
            .merging([kSecMatchLimit as String: kSecMatchLimitOne]) { _, new in new }
        // Suppress the auth UI on the existence probe. With a
        // `.userPresence` ACL on the existing entry, SecItemCopyMatching
        // would otherwise prompt for Touch ID even though we are about
        // to overwrite the value — a redundant prompt on every store.
        // UISkip falls back to errSecInteractionNotAllowed which we
        // treat as "entry exists" via the existing switch below.
        if dataProtection {
            probe[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUISkip
        }

        var probeStatus = OSStatus(errSecSuccess)
        var attempts = 0
        repeat {
            probeStatus = SecItemCopyMatching(probe as CFDictionary, nil)
            attempts += 1
        } while probeStatus == errSecAuthFailed && attempts < 2

        // KC-2: probe itself can return errSecMissingEntitlement on an
        // ad-hoc binary. Translate to the typed degraded-posture error
        // before any write attempt.
        if probeStatus == errSecMissingEntitlement && dataProtection {
            recordDegradedPosture(operation: "store-probe", status: probeStatus)
            throw KeychainStoreError.degradedNoEntitlement
        }

        // KC-1: build the AccessControl up front so any failure reports
        // before we touch the keychain. nil for legacy / opt-out paths.
        let accessControl = dataProtection ? try makeAccessControl(policy: policy) : nil

        // SL-3: build a CFData around the passphrase bytes WITHOUT copying.
        // CFDataCreateWithBytesNoCopy + kCFAllocatorNull tells CF to use
        // the buffer in place and never free it. The buffer lives inside
        // the SecureBytes-backed mlock'd page, which is wiped via
        // memset_s on the SecureBytes deinit / scope exit. CFRelease on
        // cfData therefore does not leak unwiped cleartext into the CF
        // allocator pool, and SecItem* APIs copy the bytes into their
        // own internal buffer (which is outside our control either way).
        try passphrase.withUnsafeBytes { (buf: UnsafeBufferPointer<UInt8>) in
            guard buf.count > 0, let base = buf.baseAddress else {
                // SL-8: refuse zero-length writes — they would create a
                // useless keychain entry and crash the rawLookup
                // SecureBytes precondition on read-back.
                throw KeychainStoreError.unexpectedStatus(errSecParam)
            }
            guard let cfData = CFDataCreateWithBytesNoCopy(
                kCFAllocatorDefault,
                base,
                buf.count,
                kCFAllocatorNull
            ) else {
                throw KeychainStoreError.unexpectedStatus(errSecAllocate)
            }

            // Use the same probe (sans UISkip) as the identity query for
            // SecItemUpdate; the update key set must not include
            // kSecUseAuthenticationUI.
            let updateQuery = baseQuery(fingerprint: fingerprint, dataProtection: dataProtection)
                .merging([kSecMatchLimit as String: kSecMatchLimitOne]) { _, new in new }

            // errSecInteractionNotAllowed surfaces when the existence
            // probe was suppressed (UISkip + ACL-locked entry). The
            // entry exists from our perspective; route through the
            // update path. Same for errSecSuccess.
            let entryExists = probeStatus == errSecSuccess
                || probeStatus == errSecInteractionNotAllowed
            if entryExists {
                let attrs = writeAttributes(
                    label: resolvedLabel,
                    data: cfData,
                    dataProtection: dataProtection,
                    accessControl: accessControl,
                    policy: policy
                )
                var status = OSStatus(errSecSuccess)
                var tries = 0
                repeat {
                    status = SecItemUpdate(updateQuery as CFDictionary, attrs as CFDictionary)
                    tries += 1
                } while status == errSecAuthFailed && tries < 2
                try translateWriteStatus(status, dataProtection: dataProtection, op: "update")
            } else if probeStatus == errSecItemNotFound {
                // Add new. Merge identity attributes with write attrs.
                var add = baseQuery(fingerprint: fingerprint, dataProtection: dataProtection)
                for (k, v) in writeAttributes(
                    label: resolvedLabel,
                    data: cfData,
                    dataProtection: dataProtection,
                    accessControl: accessControl,
                    policy: policy
                ) {
                    add[k] = v
                }
                var status = OSStatus(errSecSuccess)
                var tries = 0
                repeat {
                    status = SecItemAdd(add as CFDictionary, nil)
                    tries += 1
                } while status == errSecAuthFailed && tries < 2
                try translateWriteStatus(status, dataProtection: dataProtection, op: "add")
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
        case errSecMissingEntitlement where dataProtection:
            recordDegradedPosture(operation: "clear", status: status)
            // Idempotent contract: we can't delete what we can't see.
            return
        default:
            throw KeychainStoreError.unexpectedStatus(status)
        }
    }

    // MARK: Helpers

    private func translateWriteStatus(
        _ status: OSStatus,
        dataProtection: Bool,
        op: String
    ) throws {
        switch status {
        case errSecSuccess:
            return
        case errSecUserCanceled:
            throw KeychainStoreError.userCanceled
        case errSecMissingEntitlement where dataProtection:
            recordDegradedPosture(operation: "store-\(op)", status: status)
            throw KeychainStoreError.degradedNoEntitlement
        default:
            throw KeychainStoreError.unexpectedStatus(status)
        }
    }

    /// Set the process-wide degraded-posture flag and emit a single
    /// os_log line on first occurrence (FV-1). Subsequent calls are
    /// silent — the UI has already been told via
    /// `KeychainStore.degradedPostureObserved`.
    private func recordDegradedPosture(operation: String, status: OSStatus) {
        let firstTime = entitlementLogFlag.withLock { state -> Bool in
            let was = state
            state = true
            return !was
        }
        if firstTime {
            keychainLogger.error("""
                Data-protection keychain refused \(operation, privacy: .public): \
                OSStatus=\(status, privacy: .public). \
                Binary lacks application-identifier entitlement (typical for \
                ad-hoc-signed builds). Degraded posture: cached writes are \
                disabled, only legacy reads continue. UI should surface this \
                via KeychainStore.degradedPostureObserved.
                """)
        }
    }
}

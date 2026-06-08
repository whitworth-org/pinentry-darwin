// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// KeychainStoreTests: round-trip tests against the real macOS Keychain.
//
// These tests touch the developer's keychain and may trigger an "allow access"
// prompt the first time they run. They are gated behind the
// PINENTRY_DARWIN_RUN_KEYCHAIN_TESTS=1 environment variable so a plain
// `swift test` run stays hermetic. Each test uses a unique service name
// (UUID-suffixed) so a stray pinentry-mac entry under service="GnuPG" cannot
// be observed or modified.
//
// To run:   PINENTRY_DARWIN_RUN_KEYCHAIN_TESTS=1 swift test --filter KeychainStoreTests

import XCTest
@testable import KeychainStore
import SecureMemory
import LocalAuthentication

final class KeychainStoreTests: XCTestCase {

    // MARK: - Gating

    private static var enabled: Bool {
        ProcessInfo.processInfo.environment["PINENTRY_DARWIN_RUN_KEYCHAIN_TESTS"] == "1"
    }

    private func skipIfDisabled() throws {
        if !Self.enabled {
            throw XCTSkip("set PINENTRY_DARWIN_RUN_KEYCHAIN_TESTS=1 to run")
        }
    }

    // MARK: - Helpers

    /// Build a `(KeychainStore, fingerprint)` pair where `service` is unique
    /// per call. Using a per-test service keeps these tests from observing or
    /// disturbing real `service="GnuPG"` entries on the developer's machine.
    ///
    /// `useDataProtectionKeychain: false` keeps these tests on the legacy
    /// keychain. The `swift test` binary is typically ad-hoc-signed and
    /// cannot establish a stable data-protection-keychain identity, so
    /// hitting that path here would surface as errSecMissingEntitlement.
    /// Production code uses the default (true) which routes through the
    /// modern, code-signature-ACL'd keychain.
    ///
    /// `useSecureEnclaveWrap: false` isolates the raw keychain layer from
    /// the Tier 3 SE wrap path. Production `lookup` threads a
    /// `SETDESC`-derived `LAContext` through `AssuanLoop` to unwrap; the
    /// raw-keychain tests below construct no such context and only need
    /// to exercise store/lookup/clear of plain bytes. SE wrap has its
    /// own coverage in `SecureEnclaveWrapTests`.
    private func makeStore() -> (KeychainStore, String) {
        let unique = UUID().uuidString
        return (
            KeychainStore(
                service: "GnuPG-test-\(unique)",
                useDataProtectionKeychain: false,
                useSecureEnclaveWrap: false
            ),
            "fingerprint-\(unique)"
        )
    }

    /// Convenience: build a SecureBytes from a Swift array. Used only for
    /// test inputs — production passphrases enter as bytes from the Assuan
    /// parser.
    private func secureBytes(_ bytes: [UInt8]) -> SecureBytes {
        bytes.withUnsafeBufferPointer { SecureBytes(copying: $0) }
    }

    /// Read a SecureBytes back into a [UInt8] for assertions. Test-only.
    private func read(_ bytes: SecureBytes) -> [UInt8] {
        bytes.withUnsafeBytes { buf in Array(buf) }
    }

    // MARK: - Round trip

    func testStoreLookupClearRoundTrip() throws {
        try skipIfDisabled()

        let (store, fpr) = makeStore()
        defer { try? store.clear(fingerprint: fpr) }

        let secret: [UInt8] = Array("hunter2".utf8)
        try store.store(fingerprint: fpr, label: "test@example.com", passphrase: secureBytes(secret))

        let got = try store.lookup(fingerprint: fpr)
        XCTAssertNotNil(got)
        XCTAssertEqual(read(got!), secret)

        try store.clear(fingerprint: fpr)
        XCTAssertNil(try store.lookup(fingerprint: fpr))
    }

    // MARK: - Overwrite

    func testStoreOverwrite() throws {
        try skipIfDisabled()

        let (store, fpr) = makeStore()
        defer { try? store.clear(fingerprint: fpr) }

        try store.store(fingerprint: fpr, label: "first", passphrase: secureBytes(Array("first".utf8)))
        try store.store(fingerprint: fpr, label: "second", passphrase: secureBytes(Array("second".utf8)))

        let got = try store.lookup(fingerprint: fpr)
        XCTAssertEqual(read(got!), Array("second".utf8))
    }

    // MARK: - Lookup miss

    func testLookupNotFound() throws {
        try skipIfDisabled()

        let (store, fpr) = makeStore()
        XCTAssertNil(try store.lookup(fingerprint: fpr))
    }

    // MARK: - Clear is idempotent

    func testClearIdempotent() throws {
        try skipIfDisabled()

        let (store, fpr) = makeStore()
        // Clearing a non-existent entry must not throw.
        XCTAssertNoThrow(try store.clear(fingerprint: fpr))
        XCTAssertNoThrow(try store.clear(fingerprint: fpr))
    }

    // MARK: - Nil label uses service name fallback

    func testStoreWithNilLabel() throws {
        try skipIfDisabled()

        let (store, fpr) = makeStore()
        defer { try? store.clear(fingerprint: fpr) }

        try store.store(fingerprint: fpr, label: nil, passphrase: secureBytes(Array("p".utf8)))
        let got = try store.lookup(fingerprint: fpr)
        XCTAssertEqual(read(got!), Array("p".utf8))
    }

    // MARK: - KC-12: legacy reads are read-only compatibility

    /// Plant an entry on the legacy backend, then look it up through a
    /// data-protection-primary store. The value must be returned, the
    /// legacy entry must SURVIVE (no promote-and-delete laundering), and
    /// nothing must be written to the data-protection store as a side
    /// effect of the legacy read.
    ///
    /// On a properly-signed binary the data-protection probe succeeds and
    /// the migration branch is reachable: the pre-fix code re-stored the
    /// bytes into the DP/SE store and deleted the legacy entry, so this
    /// test fails without the fix. On an ad-hoc-signed `swift test` binary
    /// the DP probe degrades to a read-only legacy probe, so the entry is
    /// preserved on both code paths — the test still passes, just without
    /// exercising the migration branch.
    func testLegacyEntryIsServedReadOnlyNotPromoted() throws {
        try skipIfDisabled()

        let unique = UUID().uuidString
        let service = "GnuPG-migrate-test-\(unique)"
        let fpr = "fingerprint-\(unique)"

        // Legacy-backend store used to plant + inspect the legacy entry.
        let legacy = KeychainStore(
            service: service,
            useDataProtectionKeychain: false,
            useSecureEnclaveWrap: false
        )
        // Data-protection-primary store under the SAME service — this is
        // the production lookup path that probes legacy on a DP miss.
        let dp = KeychainStore(
            service: service,
            useDataProtectionKeychain: true,
            useSecureEnclaveWrap: false
        )
        defer {
            try? legacy.clear(fingerprint: fpr)
            try? dp.clear(fingerprint: fpr)
        }

        let secret = Array("legacy-secret".utf8)
        try legacy.store(fingerprint: fpr, label: nil, passphrase: secureBytes(secret))

        // Look up through the DP-primary store; the value must come back.
        let got = try dp.lookup(fingerprint: fpr)
        XCTAssertNotNil(got, "legacy entry must be served read-only on a DP miss")
        XCTAssertEqual(read(got!), secret)

        // The legacy entry must still be present — NOT deleted by a
        // promote-and-delete migration.
        let legacyStill = try legacy.lookup(fingerprint: fpr)
        XCTAssertNotNil(legacyStill, "legacy entry must NOT be deleted by a read")
        XCTAssertEqual(read(legacyStill!), secret)
    }

    // MARK: - SL-5: corrupt SE handle must not delete the keychain row

    private func skipUnlessSERunEnabled() throws {
        if !SecureEnclaveWrap.isAvailable {
            throw XCTSkip("SecureEnclave unavailable on this host")
        }
        let env = ProcessInfo.processInfo.environment
        if env["PINENTRY_DARWIN_RUN_SE_TESTS"] != "1"
            || env["PINENTRY_DARWIN_RUN_KEYCHAIN_TESTS"] != "1" {
            throw XCTSkip("set PINENTRY_DARWIN_RUN_SE_TESTS=1 and PINENTRY_DARWIN_RUN_KEYCHAIN_TESTS=1 (will prompt for Touch ID)")
        }
    }

    /// A corrupt wrap-key handle must be a cache MISS that preserves the
    /// real keychain row — `lookup` returns nil (forcing a re-prompt) but
    /// the underlying entry survives so a fresh store can re-wrap it. The
    /// pre-fix code routed the handle-decode failure through
    /// `authenticationFailed`, which deleted the row.
    @MainActor
    func testCorruptSEHandleDoesNotDeleteKeychainRow() throws {
        try skipUnlessSERunEnabled()

        let unique = UUID().uuidString
        let service = "GnuPG-corrupt-handle-test-\(unique)"
        let fpr = "fingerprint-\(unique)"
        // Keychain-backed handle store on the legacy backend (ad-hoc test
        // binary), unique service so it cannot disturb real handle rows.
        let handleStore = SEWrapKeyStore(
            service: "GnuPG-SEWrap-test-\(unique)",
            useDataProtectionKeychain: false
        )
        // Legacy keychain backend keeps the test off the data-protection
        // entitlement; SE wrap is independent of the storage backend.
        let store = KeychainStore(
            service: service,
            useDataProtectionKeychain: false,
            requireUserPresence: false,
            useSecureEnclaveWrap: true,
            seWrapStore: handleStore
        )
        defer { try? store.clear(fingerprint: fpr) }

        let secret = Array("hunter2".utf8)
        try store.store(fingerprint: fpr, label: nil, passphrase: secureBytes(secret))

        // Corrupt the SE handle so PrivateKey(dataRepresentation:) rejects
        // it at decode time.
        handleStore.store(dataRepresentation: Data(repeating: 0xFF, count: 32), fingerprint: fpr)

        // Lookup must be a cache miss (nil) ...
        let context = LAContext()
        let got = try store.lookup(fingerprint: fpr, context: context)
        XCTAssertNil(got, "corrupt handle must surface as a cache miss")

        // ... but the keychain row must SURVIVE so a re-store can re-wrap.
        // Read the raw (still-wrapped) bytes back via an SE-disabled store
        // pointed at the same service: a non-nil result proves the row was
        // not deleted.
        let rawReader = KeychainStore(
            service: service,
            useDataProtectionKeychain: false,
            useSecureEnclaveWrap: false
        )
        let raw = try rawReader.lookup(fingerprint: fpr)
        XCTAssertNotNil(raw, "handle-decode failure must NOT delete the keychain row")
    }

    // MARK: - FV-2: SE-unavailable downgrade is observable

    /// When the Secure Enclave is unavailable, a store that requested SE
    /// wrap falls back to an unwrapped write and flips the process-wide
    /// `secureEnclaveDowngradeObserved` posture flag. This is only
    /// exercisable on a host genuinely lacking an SE (pre-T2 Intel); CI
    /// Macs are Apple Silicon and always have an SE, so the assertion is
    /// gated on `!SecureEnclaveWrap.isAvailable`.
    func testSecureEnclaveUnavailableFlipsDowngradeFlag() throws {
        try skipIfDisabled()
        if SecureEnclaveWrap.isAvailable {
            throw XCTSkip("host has a Secure Enclave; downgrade path not reachable here")
        }

        let unique = UUID().uuidString
        let store = KeychainStore(
            service: "GnuPG-downgrade-test-\(unique)",
            useDataProtectionKeychain: false,
            requireUserPresence: false,
            useSecureEnclaveWrap: true
        )
        let fpr = "fingerprint-\(unique)"
        defer { try? store.clear(fingerprint: fpr) }

        try store.store(fingerprint: fpr, label: nil, passphrase: secureBytes(Array("p".utf8)))
        XCTAssertTrue(
            KeychainStore.secureEnclaveDowngradeObserved,
            "SE-unavailable store must flip the downgrade posture flag"
        )
    }
}

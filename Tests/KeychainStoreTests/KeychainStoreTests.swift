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
    private func makeStore() -> (KeychainStore, String) {
        let unique = UUID().uuidString
        return (
            KeychainStore(
                service: "GnuPG-test-\(unique)",
                useDataProtectionKeychain: false
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
}

// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// CacheTTLTests: Tier 4 — verifies the cacheTTLSeconds policy field is
// honoured on lookup. Like the existing KeychainStoreTests these touch
// the actual keychain and are gated by PINENTRY_DARWIN_RUN_KEYCHAIN_TESTS=1.

import XCTest
@testable import KeychainStore
import SecureMemory

final class CacheTTLTests: XCTestCase {

    private static var enabled: Bool {
        ProcessInfo.processInfo.environment["PINENTRY_DARWIN_RUN_KEYCHAIN_TESTS"] == "1"
    }

    private func skipIfDisabled() throws {
        if !Self.enabled {
            throw XCTSkip("set PINENTRY_DARWIN_RUN_KEYCHAIN_TESTS=1 to run")
        }
    }

    private func makeStore() -> (KeychainStore, String) {
        let unique = UUID().uuidString
        return (
            KeychainStore(
                service: "GnuPG-ttl-test-\(unique)",
                useDataProtectionKeychain: false,
                useSecureEnclaveWrap: false
            ),
            "fingerprint-\(unique)"
        )
    }

    private func secureBytes(_ bytes: [UInt8]) -> SecureBytes {
        bytes.withUnsafeBufferPointer { SecureBytes(copying: $0) }
    }

    private func read(_ bytes: SecureBytes) -> [UInt8] {
        bytes.withUnsafeBytes { Array($0) }
    }

    // MARK: TTL = nil → no expiry

    func testNilTTLNeverExpires() throws {
        try skipIfDisabled()
        let (store, fpr) = makeStore()
        defer { try? store.clear(fingerprint: fpr) }

        try store.store(
            fingerprint: fpr,
            label: nil,
            passphrase: secureBytes(Array("secret".utf8))
        )

        let policy = KeyPolicy(cacheTTLSeconds: nil)
        let got = try store.lookup(fingerprint: fpr, policy: policy)
        XCTAssertNotNil(got)
        XCTAssertEqual(read(got!), Array("secret".utf8))
    }

    // MARK: TTL with a future expiry → not stale

    func testFreshEntryWithLongTTLReturnsValue() throws {
        try skipIfDisabled()
        let (store, fpr) = makeStore()
        defer { try? store.clear(fingerprint: fpr) }

        try store.store(
            fingerprint: fpr,
            label: nil,
            passphrase: secureBytes(Array("secret".utf8))
        )

        let policy = KeyPolicy(cacheTTLSeconds: 3600)
        let got = try store.lookup(fingerprint: fpr, policy: policy)
        XCTAssertNotNil(got)
        XCTAssertEqual(read(got!), Array("secret".utf8))
    }

    // MARK: TTL with already-elapsed time → evicts

    func testStaleEntryIsEvicted() throws {
        try skipIfDisabled()
        let (store, fpr) = makeStore()
        defer { try? store.clear(fingerprint: fpr) }

        try store.store(
            fingerprint: fpr,
            label: nil,
            passphrase: secureBytes(Array("secret".utf8))
        )

        // TTL <= 0 maps to "no expiry" via KeyPolicy.init's coercion,
        // so use ttl=1 and sleep ~2s to force the age > ttl comparison
        // to evict.
        Thread.sleep(forTimeInterval: 2.0)

        let policy = KeyPolicy(cacheTTLSeconds: 1)
        let got = try store.lookup(fingerprint: fpr, policy: policy)
        XCTAssertNil(got, "entry older than TTL must be evicted")

        // And the entry should now be gone.
        let again = try store.lookup(fingerprint: fpr, policy: nil)
        XCTAssertNil(again)
    }
}

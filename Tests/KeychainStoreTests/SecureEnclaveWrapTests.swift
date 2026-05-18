// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// SecureEnclaveWrapTests: Tier 3 wrap/unwrap coverage.
//
// Two layers:
//   1. Always-on unit tests for the wire-format detection, SE key store
//      persistence, and error paths that do NOT require SE hardware.
//   2. Hardware round-trip tests gated by PINENTRY_DARWIN_RUN_SE_TESTS=1
//      AND `SecureEnclave.isAvailable`. These actually create an SE
//      key and perform ECDH; the .userPresence ACL means the test runner
//      will see a Touch ID prompt on unwrap. Opt-in only.

import XCTest
@testable import KeychainStore
import SecureMemory
import LocalAuthentication
import CryptoKit

final class SecureEnclaveWrapTests: XCTestCase {

    // MARK: - Wire format detection

    func testIsWrappedRejectsEmpty() {
        XCTAssertFalse(SecureEnclaveWrap.isWrapped(Data()))
    }

    func testIsWrappedRejectsSingleByte() {
        XCTAssertFalse(SecureEnclaveWrap.isWrapped(Data([0x01])))
    }

    func testIsWrappedRejectsLegacyPassphraseBytes() {
        // "hunter2" — first byte 'h' (0x68).
        XCTAssertFalse(SecureEnclaveWrap.isWrapped(Data("hunter2".utf8)))
    }

    func testIsWrappedRejectsVersion1FollowedByNonX963Marker() {
        // 0x01 0x01 — version is right but X9.63 marker is wrong.
        XCTAssertFalse(SecureEnclaveWrap.isWrapped(Data([0x01, 0x01, 0x02, 0x03])))
    }

    func testIsWrappedAcceptsVersion1AndX963Marker() {
        // 0x01 0x04 — version + X9.63 uncompressed marker.
        XCTAssertTrue(SecureEnclaveWrap.isWrapped(Data([0x01, 0x04, 0xAA, 0xBB])))
    }

    // MARK: - SEWrapKeyStore persistence

    private func ephemeralStore() -> (SEWrapKeyStore, UserDefaults) {
        let suite = "pinentry-darwin-se-test-\(UUID().uuidString)"
        guard let defaults = UserDefaults(suiteName: suite) else {
            fatalError("could not create ephemeral UserDefaults")
        }
        return (SEWrapKeyStore(defaults: defaults), defaults)
    }

    func testStoreLoadRoundTrip() {
        let (store, _) = ephemeralStore()
        let fpr = "ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD"
        let payload = Data([0xCA, 0xFE, 0xBA, 0xBE])

        XCTAssertNil(store.loadDataRepresentation(fingerprint: fpr))

        store.store(dataRepresentation: payload, fingerprint: fpr)
        XCTAssertEqual(store.loadDataRepresentation(fingerprint: fpr), payload)
    }

    func testRemoveDeletesEntry() {
        let (store, _) = ephemeralStore()
        let fpr = "ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD"
        store.store(dataRepresentation: Data([0xAA]), fingerprint: fpr)
        store.remove(fingerprint: fpr)
        XCTAssertNil(store.loadDataRepresentation(fingerprint: fpr))
    }

    func testKeyLookupIsCaseInsensitive() {
        let (store, _) = ephemeralStore()
        let lower = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
        let upper = lower.uppercased()
        store.store(dataRepresentation: Data([0xAA]), fingerprint: lower)
        XCTAssertEqual(store.loadDataRepresentation(fingerprint: upper), Data([0xAA]))
    }

    // MARK: - unwrap error paths (no SE required)

    @MainActor
    func testUnwrapRejectsShortBlob() throws {
        try skipIfNoSE()
        let (store, _) = ephemeralStore()
        let context = LAContext()
        do {
            _ = try SecureEnclaveWrap.unwrap(
                blob: Data([0x01]),
                fingerprint: "abcd",
                context: context,
                store: store
            )
            XCTFail("expected malformedBlob")
        } catch SecureEnclaveWrapError.malformedBlob {
            // expected
        }
    }

    @MainActor
    func testUnwrapRejectsBadVersion() throws {
        try skipIfNoSE()
        let (store, _) = ephemeralStore()
        let context = LAContext()
        // version 0x02 followed by 100 bytes of padding — long enough to
        // pass the minimum-length gate (1 + 65 + 28 = 94 bytes) so we
        // exercise the version check itself.
        var blob = Data([0x02])
        blob.append(contentsOf: repeatElement(UInt8(0xAA), count: 100))
        do {
            _ = try SecureEnclaveWrap.unwrap(
                blob: blob,
                fingerprint: "abcd",
                context: context,
                store: store
            )
            XCTFail("expected unsupportedVersion")
        } catch SecureEnclaveWrapError.unsupportedVersion(let v) {
            XCTAssertEqual(v, 0x02)
        }
    }

    @MainActor
    func testUnwrapRejectsBadX963Marker() throws {
        try skipIfNoSE()
        let (store, _) = ephemeralStore()
        let context = LAContext()
        // Version is right (0x01) but the pubkey byte at offset 1 is
        // not 0x04. Pad to >= minimum length.
        var blob = Data([0x01, 0x05])
        blob.append(contentsOf: repeatElement(UInt8(0x00), count: 100))
        do {
            _ = try SecureEnclaveWrap.unwrap(
                blob: blob,
                fingerprint: "abcd",
                context: context,
                store: store
            )
            XCTFail("expected malformedBlob")
        } catch SecureEnclaveWrapError.malformedBlob {
            // expected
        }
    }

    @MainActor
    func testUnwrapWithMissingSEKeyThrows() throws {
        try skipIfNoSE()
        let (store, _) = ephemeralStore()
        // Wrap a payload so we have a valid blob, but then forget the
        // SE key so unwrap finds the metadata is gone.
        let fpr = "missing-key-test"
        let context = LAContext()
        let policy = KeyPolicy(biometry: .userPresence)
        let payload = bytesOf("hunter2")
        let blob = try SecureEnclaveWrap.wrap(
            passphrase: payload,
            fingerprint: fpr,
            policy: policy,
            store: store
        )
        // Now drop the stored SE rep and try to unwrap. The unwrap
        // path should detect the missing rep and throw.
        store.remove(fingerprint: fpr)
        do {
            _ = try SecureEnclaveWrap.unwrap(
                blob: blob,
                fingerprint: fpr,
                context: context,
                store: store
            )
            XCTFail("expected missingWrapKey")
        } catch SecureEnclaveWrapError.missingWrapKey {
            // expected
        }
    }

    // MARK: - Round trip (SE hardware required)

    @MainActor
    func testWrapUnwrapRoundTrip() throws {
        try skipUnlessSERunEnabled()
        let (store, _) = ephemeralStore()
        let fpr = "round-trip-\(UUID().uuidString)"
        let plaintext = "correct horse battery staple"
        let payload = bytesOf(plaintext)
        let policy = KeyPolicy(biometry: .userPresence)

        let blob = try SecureEnclaveWrap.wrap(
            passphrase: payload,
            fingerprint: fpr,
            policy: policy,
            store: store
        )
        XCTAssertTrue(SecureEnclaveWrap.isWrapped(blob))

        let context = LAContext()
        let unwrapped = try SecureEnclaveWrap.unwrap(
            blob: blob,
            fingerprint: fpr,
            context: context,
            store: store
        )
        XCTAssertEqual(byteArray(of: unwrapped), Array(plaintext.utf8))

        SecureEnclaveWrap.deleteWrapKey(fingerprint: fpr, store: store)
    }

    @MainActor
    func testReWrapProducesDifferentBlobsButSamePlaintext() throws {
        try skipUnlessSERunEnabled()
        let (store, _) = ephemeralStore()
        let fpr = "re-wrap-\(UUID().uuidString)"
        let plaintext = "secret"
        let payload = bytesOf(plaintext)
        let policy = KeyPolicy(biometry: .userPresence)

        let blob1 = try SecureEnclaveWrap.wrap(
            passphrase: payload,
            fingerprint: fpr,
            policy: policy,
            store: store
        )
        let blob2 = try SecureEnclaveWrap.wrap(
            passphrase: payload,
            fingerprint: fpr,
            policy: policy,
            store: store
        )
        // Same SE key, different ephemerals → different blobs.
        XCTAssertNotEqual(blob1, blob2)

        // Both round-trip to the same plaintext.
        let context = LAContext()
        let u1 = try SecureEnclaveWrap.unwrap(blob: blob1, fingerprint: fpr, context: context, store: store)
        let u2 = try SecureEnclaveWrap.unwrap(blob: blob2, fingerprint: fpr, context: context, store: store)
        XCTAssertEqual(byteArray(of: u1), Array(plaintext.utf8))
        XCTAssertEqual(byteArray(of: u2), Array(plaintext.utf8))

        SecureEnclaveWrap.deleteWrapKey(fingerprint: fpr, store: store)
    }

    // MARK: - Helpers

    private func bytesOf(_ s: String) -> SecureBytes {
        Array(s.utf8).withUnsafeBufferPointer { SecureBytes(copying: $0) }
    }

    private func byteArray(of secure: SecureBytes) -> [UInt8] {
        secure.withUnsafeBytes { Array($0) }
    }

    private func skipIfNoSE() throws {
        if !SecureEnclaveWrap.isAvailable {
            throw XCTSkip("SecureEnclave unavailable on this host")
        }
    }

    private func skipUnlessSERunEnabled() throws {
        try skipIfNoSE()
        if ProcessInfo.processInfo.environment["PINENTRY_DARWIN_RUN_SE_TESTS"] != "1" {
            throw XCTSkip("set PINENTRY_DARWIN_RUN_SE_TESTS=1 to exercise SE hardware paths (will prompt for Touch ID)")
        }
    }
}

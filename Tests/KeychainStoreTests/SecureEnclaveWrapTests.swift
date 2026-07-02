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

    // MARK: - SL-5: handle-decode failure is a distinct error case

    /// `keyHandleDecodeFailed` must be a value distinct from
    /// `authenticationFailed` so the keychain layer can tell a corrupt
    /// handle (drop only the wrap key) from a genuine auth failure (delete
    /// the row). This guards the Equatable contract the catch-site relies
    /// on; it needs no SE hardware.
    func testHandleDecodeErrorIsDistinctFromAuthFailure() {
        XCTAssertNotEqual(
            SecureEnclaveWrapError.keyHandleDecodeFailed,
            SecureEnclaveWrapError.authenticationFailed
        )
        XCTAssertEqual(
            SecureEnclaveWrapError.keyHandleDecodeFailed,
            SecureEnclaveWrapError.keyHandleDecodeFailed
        )
    }

    // MARK: - SEWrapKeyStore persistence (keychain-backed, SL-4)
    //
    // The wrap-key handle now lives in the data-protection keychain rather
    // than UserDefaults (SL-4: UserDefaults is same-user-enumerable). These
    // round-trips therefore touch the real keychain and are gated behind
    // PINENTRY_DARWIN_RUN_KEYCHAIN_TESTS=1, like KeychainStoreTests. Each
    // uses a unique service name and the legacy backend (the swift-test
    // binary is ad-hoc-signed and cannot use the data-protection backend).

    private static var keychainTestsEnabled: Bool {
        ProcessInfo.processInfo.environment["PINENTRY_DARWIN_RUN_KEYCHAIN_TESTS"] == "1"
    }

    private func skipIfKeychainDisabled() throws {
        if !Self.keychainTestsEnabled {
            throw XCTSkip("set PINENTRY_DARWIN_RUN_KEYCHAIN_TESTS=1 to run keychain-backed handle-store tests")
        }
    }

    /// A keychain-backed handle store on a unique service so it cannot
    /// observe or disturb real GnuPG-SEWrap rows, on the legacy backend so
    /// an ad-hoc-signed test binary does not hit errSecMissingEntitlement.
    private func keychainHandleStore() -> SEWrapKeyStore {
        SEWrapKeyStore(
            service: "GnuPG-SEWrap-test-\(UUID().uuidString)",
            useDataProtectionKeychain: false
        )
    }

    func testStoreLoadRoundTrip() throws {
        try skipIfKeychainDisabled()
        let store = keychainHandleStore()
        let fpr = "ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD"
        let payload = Data([0xCA, 0xFE, 0xBA, 0xBE])
        defer { store.remove(fingerprint: fpr) }

        XCTAssertNil(store.loadDataRepresentation(fingerprint: fpr))

        store.store(dataRepresentation: payload, fingerprint: fpr)
        XCTAssertEqual(store.loadDataRepresentation(fingerprint: fpr), payload)
    }

    func testStoreOverwritesExistingHandle() throws {
        try skipIfKeychainDisabled()
        let store = keychainHandleStore()
        let fpr = "ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD"
        defer { store.remove(fingerprint: fpr) }

        store.store(dataRepresentation: Data([0x01, 0x02]), fingerprint: fpr)
        store.store(dataRepresentation: Data([0x03, 0x04, 0x05]), fingerprint: fpr)
        XCTAssertEqual(store.loadDataRepresentation(fingerprint: fpr), Data([0x03, 0x04, 0x05]))
    }

    func testRemoveDeletesEntry() throws {
        try skipIfKeychainDisabled()
        let store = keychainHandleStore()
        let fpr = "ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD"
        store.store(dataRepresentation: Data([0xAA]), fingerprint: fpr)
        store.remove(fingerprint: fpr)
        XCTAssertNil(store.loadDataRepresentation(fingerprint: fpr))
        // Idempotent: a second remove must not throw.
        XCTAssertNoThrow(store.remove(fingerprint: fpr))
    }

    func testKeyLookupIsCaseInsensitive() throws {
        try skipIfKeychainDisabled()
        let store = keychainHandleStore()
        let lower = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
        let upper = lower.uppercased()
        defer { store.remove(fingerprint: lower) }
        store.store(dataRepresentation: Data([0xAA]), fingerprint: lower)
        XCTAssertEqual(store.loadDataRepresentation(fingerprint: upper), Data([0xAA]))
    }

    // MARK: - unwrap error paths (no SE key material used)
    //
    // These tests exercise blob validation only and never touch SE key
    // material, but they still require SE availability: `unwrap` fail-closes
    // with `enclaveUnavailable` before any parsing when `isAvailable` is
    // false, so on a non-SE host they would see the wrong error. Hence
    // `skipIfNoSE()` — do not remove it.

    @MainActor
    func testUnwrapRejectsShortBlob() throws {
        try skipIfNoSE()
        let store = keychainHandleStore()
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
        let store = keychainHandleStore()
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
        let store = keychainHandleStore()
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
        // Calls SecureEnclaveWrap.wrap, which generates a real SE key.
        // Requires both SE availability AND the PINENTRY_DARWIN_RUN_SE_TESTS
        // env-var opt-in (via skipUnlessSERunEnabled), so developer machines
        // do not silently consume SE key slots when running the suite
        // without intent.
        try skipUnlessSERunEnabled()
        let store = keychainHandleStore()
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
        let store = keychainHandleStore()
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
        let store = keychainHandleStore()
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

    // MARK: - SL-5: AAD binds the blob to its fingerprint

    /// A blob sealed under fingerprint A must NOT open under fingerprint B,
    /// even when B's keychain row holds A's wrap-key handle (the relocation
    /// attack). With the fingerprint authenticated as AES-GCM AAD the tag
    /// check fails and unwrap reports `authenticationFailed`, which the
    /// caller treats as a cache miss.
    @MainActor
    func testUnwrapWithDifferentFingerprintFailsAuth() throws {
        try skipUnlessSERunEnabled()
        let store = keychainHandleStore()
        let fprA = "aaaa-\(UUID().uuidString)"
        let fprB = "bbbb-\(UUID().uuidString)"
        let plaintext = "correct horse battery staple"
        let payload = bytesOf(plaintext)
        let policy = KeyPolicy(biometry: .userPresence)
        defer {
            SecureEnclaveWrap.deleteWrapKey(fingerprint: fprA, store: store)
            SecureEnclaveWrap.deleteWrapKey(fingerprint: fprB, store: store)
        }

        // Seal under A, then relocate A's handle into B's slot so the SE
        // ECDH and HKDF steps succeed — only the AAD differs.
        let blob = try SecureEnclaveWrap.wrap(
            passphrase: payload, fingerprint: fprA, policy: policy, store: store
        )
        guard let aHandle = store.loadDataRepresentation(fingerprint: fprA) else {
            return XCTFail("expected a stored handle for fingerprint A")
        }
        store.store(dataRepresentation: aHandle, fingerprint: fprB)

        let context = LAContext()
        // Sanity: A still round-trips with its own AAD.
        let okA = try SecureEnclaveWrap.unwrap(
            blob: blob, fingerprint: fprA, context: context, store: store
        )
        XCTAssertEqual(byteArray(of: okA), Array(plaintext.utf8))

        // The relocated blob must NOT decrypt under B — AAD mismatch.
        do {
            _ = try SecureEnclaveWrap.unwrap(
                blob: blob, fingerprint: fprB, context: context, store: store
            )
            XCTFail("expected authenticationFailed: AAD must bind blob to fingerprint")
        } catch SecureEnclaveWrapError.authenticationFailed {
            // expected
        }
    }

    // MARK: - SL-5: corrupt wrap-key handle is a decode failure, not auth

    /// A handle whose bytes are corrupt must surface as
    /// `keyHandleDecodeFailed` (so the caller drops only the regenerable
    /// wrap key) rather than `authenticationFailed` (which would delete the
    /// user's real keychain row).
    @MainActor
    func testUnwrapWithCorruptHandleReportsDecodeFailure() throws {
        try skipUnlessSERunEnabled()
        let store = keychainHandleStore()
        let fpr = "corrupt-\(UUID().uuidString)"
        let policy = KeyPolicy(biometry: .userPresence)
        defer { SecureEnclaveWrap.deleteWrapKey(fingerprint: fpr, store: store) }

        let blob = try SecureEnclaveWrap.wrap(
            passphrase: bytesOf("hunter2"), fingerprint: fpr, policy: policy, store: store
        )
        // Overwrite the stored handle with garbage that the SE will reject
        // at PrivateKey(dataRepresentation:) decode time.
        store.store(dataRepresentation: Data(repeating: 0xFF, count: 32), fingerprint: fpr)

        let context = LAContext()
        do {
            _ = try SecureEnclaveWrap.unwrap(
                blob: blob, fingerprint: fpr, context: context, store: store
            )
            XCTFail("expected keyHandleDecodeFailed")
        } catch SecureEnclaveWrapError.keyHandleDecodeFailed {
            // expected — distinct from authenticationFailed.
        }
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

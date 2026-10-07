// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// KeychainPayloadCopyTests: how a CFData read back from the keychain becomes
// SecureBytes. Hermetic: no keychain access.

import SecureMemory
import XCTest
@testable import KeychainStore

final class KeychainPayloadCopyTests: XCTestCase {

    func testCopiesPayloadBytes() throws {
        let payload: [UInt8] = [0x70, 0x61, 0x73, 0x73]
        let copied = try XCTUnwrap(KeychainStore.copySecureBytes(from: Data(payload) as CFData))
        XCTAssertEqual(copied.withSpan { span in (0..<span.count).map { span[$0] } }, payload)
    }

    func testEmptyPayloadIsTreatedAsMiss() throws {
        XCTAssertNil(try KeychainStore.copySecureBytes(from: Data() as CFData))
    }

    // The legacy file keychain is writable by any same-user process, so an
    // entry larger than SecureBytes.maxLength can be planted. It must read
    // as a miss rather than trap SecureBytes(copying:)'s precondition.
    func testOversizedPayloadIsTreatedAsMiss() throws {
        let oversized = Data(count: SecureBytes.maxLength + 1)
        XCTAssertNil(try KeychainStore.copySecureBytes(from: oversized as CFData))
    }

    func testPayloadAtMaxLengthIsCopied() throws {
        let atLimit = Data(repeating: 0x41, count: SecureBytes.maxLength)
        let copied = try XCTUnwrap(KeychainStore.copySecureBytes(from: atLimit as CFData))
        XCTAssertEqual(copied.count, SecureBytes.maxLength)
    }
}

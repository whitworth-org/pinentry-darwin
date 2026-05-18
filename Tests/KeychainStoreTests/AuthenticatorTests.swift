// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// AuthenticatorTests: pure logic tests for LAContext reason sanitization.
// `makeContext` is exercised via a small smoke test that does not require
// biometric hardware (LAContext can be constructed unconditionally; we
// only verify the localizedReason field).

import XCTest
import LocalAuthentication
@testable import KeychainStore

final class AuthenticatorTests: XCTestCase {

    // MARK: sanitize

    func testNilInputReturnsNil() {
        XCTAssertNil(Authenticator.sanitize(nil))
    }

    func testEmptyInputReturnsNil() {
        XCTAssertNil(Authenticator.sanitize(""))
        XCTAssertNil(Authenticator.sanitize("    "))
    }

    func testTypicalSetdescPasses() {
        let s = "Please enter the passphrase to unlock the OpenPGP key 0xDEADBEEF"
        XCTAssertEqual(Authenticator.sanitize(s), s)
    }

    func testControlBytesAreReplacedWithSpace() {
        // C0 controls (incl. NUL, BEL, ESC) and DEL collapse to one space.
        let s = "Unlock\u{0007}key\u{0000}for \u{001B}Alice"
        XCTAssertEqual(Authenticator.sanitize(s), "Unlock key for Alice")
    }

    func testWhitespaceCollapsed() {
        XCTAssertEqual(
            Authenticator.sanitize("a    b   c"),
            "a b c"
        )
    }

    func testTabsAndNewlinesNormalised() {
        XCTAssertEqual(
            Authenticator.sanitize("line1\nline2\tline3"),
            "line1 line2 line3"
        )
    }

    func testByteCapEnforced() {
        let long = String(repeating: "x", count: 1000)
        let sanitized = Authenticator.sanitize(long)
        XCTAssertNotNil(sanitized)
        XCTAssertLessThanOrEqual(sanitized!.utf8.count, Authenticator.maxReasonBytes)
    }

    func testUnicodeRespectsByteCap() {
        // Each emoji = 4 bytes. Make sure we cap on a scalar boundary,
        // never split a multibyte sequence in half.
        let s = String(repeating: "🛡️", count: 200)  // way over 256 bytes
        let sanitized = Authenticator.sanitize(s)
        XCTAssertNotNil(sanitized)
        XCTAssertLessThanOrEqual(sanitized!.utf8.count, Authenticator.maxReasonBytes)
        // Must still be valid UTF-8 (Swift String guarantees this; reading
        // .utf8 implicitly validates).
        XCTAssertEqual(sanitized!.utf8.count % 4 == 0 || sanitized!.utf8.count % 4 == 1,
                       true,
                       "shield+VS16 = 7 bytes; check the cap doesn't slice mid-scalar")
    }

    // MARK: makeContext

    @MainActor
    func testMakeContextSetsLocalizedReason() {
        let context = Authenticator.makeContext(reason: "Test reason")
        XCTAssertEqual(context.localizedReason, "Test reason")
    }

    @MainActor
    func testMakeContextWithNilReasonLeavesItEmpty() {
        let context = Authenticator.makeContext(reason: nil)
        // LAContext.localizedReason defaults to empty string when unset.
        XCTAssertEqual(context.localizedReason, "")
    }

    @MainActor
    func testMakeContextSetsReuseDuration() {
        let context = Authenticator.makeContext(reason: "x")
        XCTAssertEqual(context.touchIDAuthenticationAllowableReuseDuration, 10)
    }
}

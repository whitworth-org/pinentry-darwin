// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// MnemonicTests — pin the GTK mnemonic stripping rules.

import XCTest
@testable import AssuanProtocol

final class MnemonicTests: XCTestCase {

    func testEmpty() {
        XCTAssertEqual(Mnemonic.strip(""), "")
    }

    func testNoUnderscore() {
        XCTAssertEqual(Mnemonic.strip("OK"), "OK")
        XCTAssertEqual(Mnemonic.strip("Save in Keychain"), "Save in Keychain")
    }

    func testLeadingUnderscore() {
        XCTAssertEqual(Mnemonic.strip("_OK"), "OK")
        XCTAssertEqual(Mnemonic.strip("_Cancel"), "Cancel")
        XCTAssertEqual(Mnemonic.strip("_Save in password manager"),
                       "Save in password manager")
    }

    func testInteriorUnderscore() {
        XCTAssertEqual(Mnemonic.strip("O_K"), "OK")
        XCTAssertEqual(Mnemonic.strip("Save in _Password Manager"),
                       "Save in Password Manager")
    }

    func testEscapedUnderscore() {
        XCTAssertEqual(Mnemonic.strip("__literal"), "_literal")
        XCTAssertEqual(Mnemonic.strip("foo__bar"), "foo_bar")
    }

    // "__" escapes a literal underscore; the next "_b" is then a mnemonic.
    func testEscapedThenMnemonic() {
        XCTAssertEqual(Mnemonic.strip("foo___bar"), "foo_bar")
    }

    // GTK convention: a dangling trailing "_" is malformed; drop it.
    func testTrailingUnderscoreDropped() {
        XCTAssertEqual(Mnemonic.strip("foo_"), "foo")
    }

    func testLoneUnderscore() {
        XCTAssertEqual(Mnemonic.strip("_"), "")
    }

    func testOptionalNilFlowsThrough() {
        let s: String? = nil
        XCTAssertNil(Mnemonic.stripOptional(s))
    }

    func testOptionalSomeStripped() {
        let s: String? = "_OK"
        XCTAssertEqual(Mnemonic.stripOptional(s), "OK")
    }

    // Real-world labels lifted from gpg-agent's OPTION shipments.
    func testGpgAgentRealWorldShipments() {
        XCTAssertEqual(Mnemonic.strip("_OK"), "OK")
        XCTAssertEqual(Mnemonic.strip("_Cancel"), "Cancel")
        XCTAssertEqual(Mnemonic.strip("_Yes"), "Yes")
        XCTAssertEqual(Mnemonic.strip("_No"), "No")
        XCTAssertEqual(Mnemonic.strip("_Save in password manager"),
                       "Save in password manager")
    }
}

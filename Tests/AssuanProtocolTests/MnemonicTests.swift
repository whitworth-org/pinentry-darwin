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

    // FV-6 regression: bidi-override / zero-width / BOM codepoints
    // must be dropped from button labels so a hostile gpg-agent cannot
    // visually swap "OK" and "Cancel" via U+202E + similar tricks.
    func testStripsRTLOverride() {
        // SETOK with embedded RLO ("_O\u{202E}K"). The mnemonic strip
        // removes the leading underscore; FV-6 then drops U+202E so
        // the visible label is the structural "OK".
        XCTAssertEqual(Mnemonic.strip("_O\u{202E}K"), "OK")
    }

    func testStripsLRO() {
        XCTAssertEqual(Mnemonic.strip("_C\u{202D}ancel"), "Cancel")
    }

    func testStripsZeroWidthSpace() {
        XCTAssertEqual(Mnemonic.strip("OK\u{200B}"), "OK")
        XCTAssertEqual(Mnemonic.strip("_Y\u{200B}es"), "Yes")
    }

    func testStripsBidiIsolate() {
        XCTAssertEqual(Mnemonic.strip("_O\u{2068}K\u{2069}"), "OK")
    }

    func testStripsBOM() {
        XCTAssertEqual(Mnemonic.strip("\u{FEFF}OK"), "OK")
    }
}

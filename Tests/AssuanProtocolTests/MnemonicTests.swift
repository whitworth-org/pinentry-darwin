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

    // MARK: - sanitiseBody

    func testSanitiseBodyEmptyAndPlain() {
        XCTAssertEqual(Mnemonic.sanitiseBody(""), "")
        XCTAssertEqual(Mnemonic.sanitiseBody("Please enter the passphrase"),
                       "Please enter the passphrase")
    }

    // sanitiseBody is for body text, not button labels — underscores are
    // legitimate content and must survive (unlike Mnemonic.strip).
    func testSanitiseBodyKeepsUnderscores() {
        XCTAssertEqual(Mnemonic.sanitiseBody("_OK"), "_OK")
        XCTAssertEqual(Mnemonic.sanitiseBody("foo_bar"), "foo_bar")
    }

    // The security contract: no FV-6 scalar appears in the output,
    // regardless of how Swift's grapheme segmentation groups the input.
    // We don't assert "AB → AB" because Swift's clustering binds some
    // format scalars (ZWJ U+200D, ZWNJ U+200C) to the preceding letter,
    // and the safer behaviour is to drop the whole cluster — including
    // the letter. The legitimacy of the letter is undecidable once an
    // adversarial format codepoint is attached to it.
    func testSanitiseBodyDropsZeroWidthRange() {
        // U+200B-U+200F: zero-width space through RLM.
        for v: UInt32 in 0x200B...0x200F {
            let scalar = Unicode.Scalar(v)!
            let out = Mnemonic.sanitiseBody("A" + String(scalar) + "B")
            XCTAssertFalse(
                out.unicodeScalars.contains(scalar),
                "scalar U+\(String(v, radix: 16, uppercase: true)) leaked into '\(out)'"
            )
        }
    }

    func testSanitiseBodyDropsLegacyBidiOverrideRange() {
        // U+202A-U+202E: LRE / RLE / PDF / LRO / RLO.
        for v: UInt32 in 0x202A...0x202E {
            let scalar = Unicode.Scalar(v)!
            let out = Mnemonic.sanitiseBody("A" + String(scalar) + "B")
            XCTAssertFalse(
                out.unicodeScalars.contains(scalar),
                "scalar U+\(String(v, radix: 16, uppercase: true)) leaked into '\(out)'"
            )
        }
    }

    func testSanitiseBodyDropsBidiIsolateRange() {
        // U+2060-U+2069: word joiner + bidi isolates.
        for v: UInt32 in 0x2060...0x2069 {
            let scalar = Unicode.Scalar(v)!
            let out = Mnemonic.sanitiseBody("A" + String(scalar) + "B")
            XCTAssertFalse(
                out.unicodeScalars.contains(scalar),
                "scalar U+\(String(v, radix: 16, uppercase: true)) leaked into '\(out)'"
            )
        }
    }

    func testSanitiseBodyDropsBOM() {
        XCTAssertEqual(Mnemonic.sanitiseBody("\u{FEFF}Hello"), "Hello")
        XCTAssertEqual(Mnemonic.sanitiseBody("Hel\u{FEFF}lo"), "Hello")
    }

    // Hostile SETDESC: leading "Unlock 0xAAAA" rewritten via RLO to
    // visually present a different fingerprint. After sanitiseBody the
    // RLO is gone and the underlying byte sequence is what gets shown.
    func testSanitiseBodyNeutralisesHostileSetdesc() {
        let hostile = "Unlock key \u{202E}AAAA\u{202C} for Alice"
        XCTAssertEqual(
            Mnemonic.sanitiseBody(hostile),
            "Unlock key AAAA for Alice"
        )
    }

    // Grapheme-cluster level drop: when an FV-6 scalar shares a cluster
    // with other scalars (combining marks, adjacent letters under Swift's
    // segmentation), the whole cluster goes. Output never carries an
    // orphan combining mark or a "joined" cluster that the attacker
    // shaped into a misleading composition.
    func testSanitiseBodyDropsClustersContainingFV6() {
        let out = Mnemonic.sanitiseBody("A\u{200D}\u{0300}B")
        XCTAssertFalse(out.unicodeScalars.contains(Unicode.Scalar(0x200D)!))
        XCTAssertFalse(out.unicodeScalars.contains(Unicode.Scalar(0x0300)!))
    }

    func testSanitiseBodyOptionalNilFlowsThrough() {
        let s: String? = nil
        XCTAssertNil(Mnemonic.sanitiseBodyOptional(s))
    }

    func testSanitiseBodyOptionalSomeFiltered() {
        let s: String? = "Hello\u{202E}world"
        XCTAssertEqual(Mnemonic.sanitiseBodyOptional(s), "Helloworld")
    }
}

// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// CommandParsingTests — covers every dispatch verb, both `key=value` and
// `key value` forms of OPTION, and the unknown-verb fallback.

import XCTest
@testable import AssuanProtocol

// MARK: - CommandParsingTests

final class CommandParsingTests: XCTestCase {

    func testBye() throws {
        XCTAssertEqual(try Command.parse("BYE"), .bye)
        XCTAssertEqual(try Command.parse("bye"), .bye)
    }

    func testReset() throws {
        XCTAssertEqual(try Command.parse("RESET"), .reset)
    }

    func testSetDescPercentDecodes() throws {
        // "Enter passphrase for:\n\"Alice\""
        let line = "SETDESC Enter+passphrase+for%3A%0A%22Alice%22"
        let parsed = try Command.parse(line)
        XCTAssertEqual(parsed, .setDesc("Enter passphrase for:\n\"Alice\""))
    }

    func testOptionFlag() throws {
        XCTAssertEqual(try Command.parse("OPTION grab"),
                       .option(key: "grab", value: nil))
    }

    func testOptionEqualsForm() throws {
        XCTAssertEqual(try Command.parse("OPTION default-ok=OK"),
                       .option(key: "default-ok", value: "OK"))
    }

    func testOptionSpaceForm() throws {
        XCTAssertEqual(try Command.parse("OPTION ttyname /dev/ttys001"),
                       .option(key: "ttyname", value: "/dev/ttys001"))
    }

    func testSetKeyInfoClear() throws {
        XCTAssertEqual(try Command.parse("SETKEYINFO --clear"),
                       .setKeyInfo(.clear))
    }

    func testSetKeyInfoKey() throws {
        let fpr = "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555"
        let parsed = try Command.parse("SETKEYINFO u/\(fpr)")
        XCTAssertEqual(parsed, .setKeyInfo(.key(mode: "u", fingerprint: fpr)))
    }

    func testSetKeyInfoSha256() throws {
        // SHA-256 fingerprint (64 hex chars) — must be accepted.
        let fpr = String(repeating: "A", count: 64)
        let parsed = try Command.parse("SETKEYINFO s/\(fpr)")
        XCTAssertEqual(parsed, .setKeyInfo(.key(mode: "s", fingerprint: fpr)))
    }

    func testSetKeyInfoLowercaseHex() throws {
        // Mixed-case hex must round-trip verbatim.
        let fpr = "abcdef0123456789abcdef0123456789ABCDEF01"
        let parsed = try Command.parse("SETKEYINFO n/\(fpr)")
        XCTAssertEqual(parsed, .setKeyInfo(.key(mode: "n", fingerprint: fpr)))
    }

    func testSetKeyInfoRejectsShort() {
        // 39 hex chars — wrong length.
        let fpr = String(repeating: "A", count: 39)
        XCTAssertThrowsError(try Command.parse("SETKEYINFO u/\(fpr)"))
    }

    func testSetKeyInfoRejectsLong() {
        // 41 hex chars — wrong length.
        let fpr = String(repeating: "A", count: 41)
        XCTAssertThrowsError(try Command.parse("SETKEYINFO u/\(fpr)"))
    }

    func testSetKeyInfoRejectsHuge() {
        // ~10 KiB of hex — would have polluted kSecAttrAccount.
        let fpr = String(repeating: "A", count: 10_000)
        XCTAssertThrowsError(try Command.parse("SETKEYINFO u/\(fpr)"))
    }

    func testSetKeyInfoRejectsNonHex() {
        // 40 chars but contains 'G' — not valid hex.
        let fpr = "GGGGAAAA1111BBBB2222CCCC3333DDDD4444EEEE"
        XCTAssertThrowsError(try Command.parse("SETKEYINFO u/\(fpr)"))
    }

    func testSetKeyInfoRejectsControlBytes() {
        // 40 "chars" including embedded NUL — would have flowed into the
        // keychain account namespace.
        let fpr = "AAAA1111BBBB2222CCCC3333DDDD4444EEEE\u{0000}55"
        XCTAssertThrowsError(try Command.parse("SETKEYINFO u/\(fpr)"))
    }

    func testIsValidFingerprintShape() {
        XCTAssertTrue(Command.isValidFingerprint(String(repeating: "0", count: 40)))
        XCTAssertTrue(Command.isValidFingerprint(String(repeating: "f", count: 64)))
        XCTAssertFalse(Command.isValidFingerprint(""))
        XCTAssertFalse(Command.isValidFingerprint(String(repeating: "A", count: 50)))
        XCTAssertFalse(Command.isValidFingerprint("/"))
        // Arabic-Indic digit ٠ is "hex" under Character.isHexDigit but
        // must NOT pass our ASCII-only validator.
        XCTAssertFalse(Command.isValidFingerprint(String(repeating: "\u{0660}", count: 40)))
    }

    // MARK: - parseUserIdFromDescription

    func testParseUserIdNilOnNilInput() {
        XCTAssertNil(Command.parseUserIdFromDescription(nil))
    }

    func testParseUserIdNilOnNoQuotes() {
        XCTAssertNil(Command.parseUserIdFromDescription("no quotes here"))
    }

    func testParseUserIdNilOnSingleQuote() {
        XCTAssertNil(Command.parseUserIdFromDescription("only one \" mark"))
    }

    func testParseUserIdPicksLastPair() {
        // gpg-agent's stock SETDESC ends with the user-id in quotes.
        // Any localised header that itself uses quotes ("a quoted prefix")
        // must not shift the label off-target.
        let desc = "Please enter the passphrase \"prefix shouldn't win\" for \"Alice <a@b>\""
        XCTAssertEqual(Command.parseUserIdFromDescription(desc), "Alice <a@b>")
    }

    func testParseUserIdRejectsEmptyPair() {
        XCTAssertNil(Command.parseUserIdFromDescription("Header with empty \"\" pair"))
    }

    func testParseUserIdCapsAt256() {
        // 300 chars of payload — must come back capped to 256.
        let payload = String(repeating: "a", count: 300)
        let result = Command.parseUserIdFromDescription("\"\(payload)\"")
        XCTAssertEqual(result?.count, 256)
    }

    func testParseUserIdRejectsControlBytes() {
        // NEL (\x85) is a Unicode control; embedded LF and BEL are also
        // common attacker-injected payloads. Any of these must drop the
        // candidate to nil rather than corrupting kSecAttrLabel.
        XCTAssertNil(Command.parseUserIdFromDescription("\"Alice\u{0007}Bob\""))
        XCTAssertNil(Command.parseUserIdFromDescription("\"Alice\nBob\""))
        XCTAssertNil(Command.parseUserIdFromDescription("\"Alice\u{007F}Bob\""))
    }

    func testParseUserIdAllowsExtendedAscii() {
        // Common UTF-8 characters in non-English user-ids must pass.
        let desc = "for \"Álice <á@b>\""
        XCTAssertEqual(Command.parseUserIdFromDescription(desc), "Álice <á@b>")
    }

    func testConfirmFlagless() throws {
        XCTAssertEqual(try Command.parse("CONFIRM"),
                       .confirm(oneButton: false))
    }

    func testConfirmOneButton() throws {
        XCTAssertEqual(try Command.parse("CONFIRM --one-button"),
                       .confirm(oneButton: true))
    }

    func testGetInfoVersion() throws {
        XCTAssertEqual(try Command.parse("GETINFO version"),
                       .getInfo(.version))
    }

    func testGetInfoFlavor() throws {
        XCTAssertEqual(try Command.parse("GETINFO flavor"),
                       .getInfo(.flavor))
    }

    func testGetInfoOther() throws {
        XCTAssertEqual(try Command.parse("GETINFO foobar"),
                       .getInfo(.other("foobar")))
    }

    func testUnknownVerbReturnsUnknown() throws {
        // Must NOT throw — Session expects to reply ERR but the parser is
        // lenient so the loop survives unknown verbs.
        let parsed = try Command.parse("FROBNICATE arg one two")
        XCTAssertEqual(parsed, .unknown(verb: "FROBNICATE", args: "arg one two"))
    }

    func testSetTimeout() throws {
        XCTAssertEqual(try Command.parse("SETTIMEOUT 30"), .setTimeout(30))
    }

    func testSetTimeoutMalformed() {
        XCTAssertThrowsError(try Command.parse("SETTIMEOUT notanumber"))
    }

    func testSetQualityBarOptionalArg() throws {
        XCTAssertEqual(try Command.parse("SETQUALITYBAR"), .setQualityBar(nil))
        XCTAssertEqual(try Command.parse("SETQUALITYBAR Quality"),
                       .setQualityBar("Quality"))
    }

    func testClearPassphrase() throws {
        XCTAssertEqual(try Command.parse("CLEARPASSPHRASE --mode=normal"),
                       .clearPassphrase(keyInfo: "--mode=normal"))
    }

    // MARK: - SETKEYINFO mode normalisation (AS-1 regression)

    func testSetKeyInfoUppercaseModeNormalisesToLower() throws {
        let fpr = String(repeating: "A", count: 40)
        // Uppercase 'U' must canonicalise to lowercase so the
        // `Spec.canSaveToKeychain` `mode == "u"` no-cache policy
        // applies. Pre-AS-1 this was retained verbatim and bypassed
        // the gate.
        let parsed = try Command.parse("SETKEYINFO U/\(fpr)")
        XCTAssertEqual(parsed, .setKeyInfo(.key(mode: "u", fingerprint: fpr)))
    }

    func testSetKeyInfoRejectsUnicodeHomoglyphMode() {
        let fpr = String(repeating: "A", count: 40)
        // U+00FA (ú) is one grapheme cluster — pre-AS-1 it slipped
        // past the `mode != "u"` Character comparison.
        XCTAssertThrowsError(try Command.parse("SETKEYINFO \u{00FA}/\(fpr)"))
        // u + combining acute = one grapheme but two scalars; reject.
        XCTAssertThrowsError(try Command.parse("SETKEYINFO u\u{0301}/\(fpr)"))
        // Cyrillic 'u'-shaped homoglyph.
        XCTAssertThrowsError(try Command.parse("SETKEYINFO \u{0438}/\(fpr)"))
    }

    func testSetKeyInfoRejectsNonLetterMode() {
        let fpr = String(repeating: "A", count: 40)
        XCTAssertThrowsError(try Command.parse("SETKEYINFO 1/\(fpr)"))
        XCTAssertThrowsError(try Command.parse("SETKEYINFO -/\(fpr)"))
        XCTAssertThrowsError(try Command.parse("SETKEYINFO  /\(fpr)"))
    }
}

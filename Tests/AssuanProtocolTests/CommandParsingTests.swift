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
}

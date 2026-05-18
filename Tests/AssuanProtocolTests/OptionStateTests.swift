// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// OptionStateTests — drive a sequence of OPTION commands through
// `OptionState.apply` and assert the resulting state.

import XCTest
@testable import AssuanProtocol

// MARK: - OptionStateTests

final class OptionStateTests: XCTestCase {

    func testGrabFlagsToggle() {
        var s = OptionState()
        s.apply(key: "grab", value: nil)
        XCTAssertTrue(s.grab)
        s.apply(key: "no-grab", value: nil)
        XCTAssertFalse(s.grab)
    }

    func testTextOptionsAccumulate() {
        var s = OptionState()
        s.apply(key: "ttyname", value: "/dev/ttys001")
        s.apply(key: "ttytype", value: "xterm-256color")
        s.apply(key: "lc-ctype", value: "en_US.UTF-8")
        s.apply(key: "lc-messages", value: "en_US.UTF-8")

        XCTAssertEqual(s.ttyName, "/dev/ttys001")
        XCTAssertEqual(s.ttyType, "xterm-256color")
        XCTAssertEqual(s.lcCType, "en_US.UTF-8")
        XCTAssertEqual(s.lcMessages, "en_US.UTF-8")
    }

    func testDefaultButtons() {
        var s = OptionState()
        s.apply(key: "default-ok", value: "OK")
        s.apply(key: "default-cancel", value: "Cancel")
        s.apply(key: "default-prompt", value: "Passphrase:")

        XCTAssertEqual(s.defaultOK, "OK")
        XCTAssertEqual(s.defaultCancel, "Cancel")
        XCTAssertEqual(s.defaultPrompt, "Passphrase:")
    }

    func testAllowExternalPasswordCache() {
        var s = OptionState()
        XCTAssertFalse(s.allowExternalPasswordCache)
        s.apply(key: "allow-external-password-cache", value: nil)
        XCTAssertTrue(s.allowExternalPasswordCache)
    }

    func testParseOwner() {
        var s = OptionState()
        s.apply(key: "owner", value: "12345/501 myhost")
        XCTAssertEqual(s.ownerPID, 12345)
        XCTAssertEqual(s.ownerUID, 501)
        XCTAssertEqual(s.ownerHost, "myhost")
    }

    func testParseOwnerPIDOnly() {
        var s = OptionState()
        s.apply(key: "owner", value: "9999")
        XCTAssertEqual(s.ownerPID, 9999)
        XCTAssertNil(s.ownerUID)
        XCTAssertNil(s.ownerHost)
    }

    func testConstraints() {
        var s = OptionState()
        s.apply(key: "constraints-enforce", value: nil)
        s.apply(key: "constraints-hint-short", value: "8+ chars")
        s.apply(key: "constraints-hint-long", value: "Use 8 or more characters.")
        s.apply(key: "constraints-error-title", value: "Too short")

        XCTAssertTrue(s.constraintsEnforce)
        XCTAssertEqual(s.constraintsHintShort, "8+ chars")
        XCTAssertEqual(s.constraintsHintLong, "Use 8 or more characters.")
        XCTAssertEqual(s.constraintsErrorTitle, "Too short")
    }

    func testUnknownOptionIgnored() {
        var s = OptionState()
        let before = s
        s.apply(key: "no-such-option", value: "whatever")
        XCTAssertEqual(s, before)
    }

    // gpg-agent ships button-style defaults with GTK mnemonic markers
    // ("_OK"). OptionState must strip them at ingestion so the View never
    // renders a literal "_OK".
    func testButtonLabelMnemonicsStripped() {
        var s = OptionState()
        s.apply(key: "default-ok", value: "_OK")
        s.apply(key: "default-cancel", value: "_Cancel")
        s.apply(key: "default-prompt", value: "_PIN:")
        s.apply(key: "default-pwmngr", value: "_Save in password manager")
        XCTAssertEqual(s.defaultOK, "OK")
        XCTAssertEqual(s.defaultCancel, "Cancel")
        XCTAssertEqual(s.defaultPrompt, "PIN:")
        XCTAssertEqual(s.defaultPwManager, "Save in password manager")
    }

    // Sentence-form options (cf-visi / capshint) are NOT stripped — they
    // carry message text where literal underscores might be intended.
    func testSentenceOptionsNotStripped() {
        var s = OptionState()
        s.apply(key: "default-cf-visi",
                value: "Make passphrase visible?")
        s.apply(key: "default-capshint", value: "Caps Lock is on")
        XCTAssertEqual(s.defaultCfVisi, "Make passphrase visible?")
        XCTAssertEqual(s.defaultCapsHint, "Caps Lock is on")
    }

    func testNoSymkeyCacheDefaultsFalse() {
        let s = OptionState()
        XCTAssertFalse(s.noSymkeyCache)
    }

    func testNoSymkeyCacheSetByOption() {
        var s = OptionState()
        s.apply(key: "no-symkey-cache", value: nil)
        XCTAssertTrue(s.noSymkeyCache)
    }

    func testNoSymkeyCacheStickyOnceSet() {
        // OPTION is a one-way latch in upstream pinentry — once
        // gpg-agent says "no caching", it stays off for the session
        // regardless of further OPTION traffic.
        var s = OptionState()
        s.apply(key: "no-symkey-cache", value: nil)
        s.apply(key: "ttyname", value: "/dev/ttys001")
        s.apply(key: "default-ok", value: "OK")
        XCTAssertTrue(s.noSymkeyCache)
    }
}

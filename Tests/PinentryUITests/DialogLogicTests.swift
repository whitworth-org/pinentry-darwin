// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// DialogLogicTests.swift — the decisions behind the dialogs' text and
// buttons, tested as pure functions: repeat/mismatch status, key-info
// formatting, button order, and button-to-result mapping.

import XCTest
@testable import PinentryUI

final class FieldStatusTests: XCTestCase {

    private func status(
        pin: Int, repeat repeatLength: Int, match: Bool,
        truncated: Bool = false, attempted: Bool = false
    ) -> FieldStatus {
        FieldStatus.evaluate(
            pinLength: pin, repeatLength: repeatLength, pinsMatch: match,
            truncated: truncated, submitAttempted: attempted)
    }

    func testEmptyRepeatShowsNothing() {
        XCTAssertEqual(status(pin: 7, repeat: 0, match: false), .hidden)
        XCTAssertEqual(status(pin: 0, repeat: 0, match: true), .hidden)
    }

    // The first keystroke of the repeat is almost always a prefix of the
    // passphrase; flagging it would be a false alarm.
    func testShorterRepeatStaysQuietWhileTyping() {
        XCTAssertEqual(status(pin: 7, repeat: 3, match: false), .hidden)
    }

    func testRepeatAsLongAsPinButDifferentIsMismatch() {
        XCTAssertEqual(status(pin: 7, repeat: 7, match: false), .mismatch)
    }

    func testRepeatLongerThanPinIsMismatch() {
        XCTAssertEqual(status(pin: 3, repeat: 7, match: false), .mismatch)
    }

    func testRepeatWithNoPinIsMismatch() {
        XCTAssertEqual(status(pin: 0, repeat: 1, match: false), .mismatch)
    }

    // Return on a disabled OK must explain itself instead of doing nothing.
    func testSubmitAttemptSurfacesShortMismatch() {
        XCTAssertEqual(status(pin: 7, repeat: 3, match: false, attempted: true), .mismatch)
    }

    func testEqualBuffersAreMatch() {
        XCTAssertEqual(status(pin: 7, repeat: 7, match: true), .match)
    }

    func testTruncationOutranksEverything() {
        XCTAssertEqual(status(pin: 0, repeat: 0, match: true, truncated: true), .tooLong)
        XCTAssertEqual(status(pin: 7, repeat: 7, match: true, truncated: true), .tooLong)
    }

    // MARK: - Text

    func testMismatchUsesGpgAgentTextWhenSupplied() {
        var spec = DialogSpec(kind: .pin)
        spec.repeatError = "Les phrases ne correspondent pas."
        XCTAssertEqual(FieldStatus.mismatch.message(for: spec), "Les phrases ne correspondent pas.")
    }

    func testMismatchFallsBackToBuiltInText() {
        var spec = DialogSpec(kind: .pin)
        XCTAssertEqual(FieldStatus.mismatch.message(for: spec), "Passphrases do not match.")
        spec.repeatError = ""
        XCTAssertEqual(FieldStatus.mismatch.message(for: spec), "Passphrases do not match.")
    }

    func testMatchSpeaksOnlyWhenGpgAgentSuppliesText() {
        var spec = DialogSpec(kind: .pin)
        XCTAssertNil(FieldStatus.match.message(for: spec))
        spec.repeatOK = "Passphrases match."
        XCTAssertEqual(FieldStatus.match.message(for: spec), "Passphrases match.")
    }

    func testHiddenHasNoMessage() {
        XCTAssertNil(FieldStatus.hidden.message(for: DialogSpec(kind: .pin)))
    }

    func testBuiltInMessagesAreTerseAndPlain() {
        let spec = DialogSpec(kind: .pin)
        for status in [FieldStatus.mismatch, .tooLong] {
            let text = status.message(for: spec) ?? ""
            XCTAssertFalse(text.isEmpty)
            XCTAssertFalse(text.contains("!"), "no exclamation marks: \(text)")
        }
    }

    func testToneIsSuccessOnlyForMatch() {
        XCTAssertEqual(FieldStatus.match.tone, .success)
        XCTAssertEqual(FieldStatus.mismatch.tone, .error)
        XCTAssertEqual(FieldStatus.tooLong.tone, .error)
    }
}

final class KeyInfoFormatTests: XCTestCase {

    func testFortyHexDigitsGroupAsGpgPrintsThem() {
        let value = KeyInfoFormat.grouped("1ea93fe7b6638f3c6b6e9c5c2abd2764d9d7175c")
        XCTAssertEqual(value, "1EA9 3FE7 B663 8F3C 6B6E  9C5C 2ABD 2764 D9D7 175C")
    }

    func testNonFingerprintStringIsShownAsGiven() {
        XCTAssertEqual(KeyInfoFormat.grouped("not-a-fingerprint"), "not-a-fingerprint")
        XCTAssertEqual(KeyInfoFormat.grouped("ABCD"), "ABCD")
        XCTAssertEqual(KeyInfoFormat.grouped(String(repeating: "Z", count: 40)),
                       String(repeating: "Z", count: 40))
    }

    func testCardAndSshModesGetACaption() {
        XCTAssertEqual(KeyInfoFormat.label(mode: "c", fingerprint: "AB").caption, "Card key")
        XCTAssertEqual(KeyInfoFormat.label(mode: "s", fingerprint: "AB").caption, "SSH key")
        XCTAssertNil(KeyInfoFormat.label(mode: "n", fingerprint: "AB").caption)
    }

    func testSpokenLabelNamesTheKeyKind() {
        XCTAssertEqual(KeyInfoFormat.label(mode: "n", fingerprint: "AB12").spoken, "Key AB12")
        XCTAssertEqual(KeyInfoFormat.label(mode: "c", fingerprint: "AB12").spoken, "Card key AB12")
    }
}

final class DialogButtonTests: XCTestCase {

    func testOKIsAlwaysLastSoItSitsOnTheRight() {
        for notOK in [nil, "", "Not now"] {
            let roles = DialogButtonRole.layout(oneButton: false, notOKLabel: notOK)
            XCTAssertEqual(roles.last, .ok)
        }
    }

    func testNotOKComesBeforeCancel() {
        XCTAssertEqual(
            DialogButtonRole.layout(oneButton: false, notOKLabel: "Don't Save"),
            [.notOK, .cancel, .ok])
    }

    func testDefaultLayoutIsCancelThenOK() {
        XCTAssertEqual(DialogButtonRole.layout(oneButton: false, notOKLabel: nil), [.cancel, .ok])
    }

    func testEmptyNotOKLabelAddsNoButton() {
        XCTAssertEqual(DialogButtonRole.layout(oneButton: false, notOKLabel: ""), [.cancel, .ok])
    }

    func testOneButtonShowsOnlyOK() {
        XCTAssertEqual(DialogButtonRole.layout(oneButton: true, notOKLabel: "Not now"), [.ok])
    }

    func testConfirmMapsButtonsToAssuanResults() {
        XCTAssertEqual(String(describing: DialogButtonRole.ok.confirmResult), "confirmed")
        XCTAssertEqual(String(describing: DialogButtonRole.notOK.confirmResult), "notConfirmed")
        XCTAssertEqual(String(describing: DialogButtonRole.cancel.confirmResult), "canceled")
    }
}

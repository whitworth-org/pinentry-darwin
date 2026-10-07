// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// DialogRenderTests.swift — hosts the three dialogs offscreen and checks
// layout invariants (bounded height, no layout shift, secure field stays
// opaque to accessibility). With PINENTRY_RENDER_DIR set, also writes
// Light and Dark PNGs of every state for visual review.

import AppKit
import SwiftUI
import XCTest
@testable import PinentryUI

@MainActor
final class DialogRenderTests: XCTestCase {

    static let fingerprint = "1EA93FE7B6638F3C6B6E9C5C2ABD2764D9D7175C"
    static let longDescription = (1...60).map { "Line \($0) of a very long description." }
        .joined(separator: "\n")

    func spec(
        _ kind: DialogSpec.Kind,
        mutate: (inout DialogSpec) -> Void = { _ in }
    ) -> DialogSpec {
        var spec = DialogSpec(kind: kind)
        spec.title = "Unlock key"
        spec.description = "Please enter the passphrase to unlock the OpenPGP secret key:\n"
            + "\"Ryan Whitworth <ryan@whitworth.org>\"\n"
            + "255-bit EDDSA key, ID D9D7175C, created 2024-03-01."
        spec.keyInfo = .key(mode: "n", fingerprint: Self.fingerprint)
        mutate(&spec)
        return spec
    }

    func pinView(_ spec: DialogSpec, pin: String = "", repeatPin: String = "") -> PinView {
        let model = PinViewModel(
            spec: spec, showTypingByDefault: false, saveByDefault: false, onResult: { _ in })
        model.setPin(from: pin)
        model.setRepeat(from: repeatPin)
        return PinView(spec: spec, model: model, secureKeyboardEntry: false)
    }

    /// Mounts in Light and Dark, saves PNGs, and returns the Light mount.
    @discardableResult
    func renderBoth(_ name: String, _ make: () -> some View) -> MountedDialog {
        let dark = MountedDialog(make(), appearance: .darkAqua)
        dark.save(named: "\(name)-dark")
        XCTAssertFalse(dark.pngData().isEmpty, "\(name) dark rendered nothing")
        let light = MountedDialog(make(), appearance: .aqua)
        light.save(named: "\(name)-light")
        XCTAssertFalse(light.pngData().isEmpty, "\(name) light rendered nothing")
        return light
    }

    // MARK: - Visual states

    func testRenderPinStates() {
        renderBoth("pin-basic") { pinView(spec(.pin)) }
        renderBoth("pin-typed") { pinView(spec(.pin), pin: "hunter2") }
        renderBoth("pin-error") {
            pinView(spec(.pin) { $0.error = "Bad Passphrase (try 2 of 3)" })
        }
        renderBoth("pin-notok") { pinView(spec(.pin) { $0.notOKLabel = "Not now" }, pin: "x") }
        renderBoth("pin-repeat-idle") {
            pinView(spec(.pin) { $0.repeatPrompt = "Repeat:" }, pin: "hunter2")
        }
        renderBoth("pin-repeat-mismatch") {
            pinView(
                spec(.pin) { $0.repeatPrompt = "Repeat:"; $0.allowKeychainSave = true },
                pin: "hunter2", repeatPin: "hunter3")
        }
        renderBoth("pin-repeat-match") {
            pinView(
                spec(.pin) { $0.repeatPrompt = "Repeat:"; $0.repeatOK = "Passphrases match." },
                pin: "hunter2", repeatPin: "hunter2")
        }
        renderBoth("pin-long-prompt") {
            pinView(spec(.pin) {
                $0.prompt = "Enter the new passphrase for this key:"
                $0.repeatPrompt = "Repeat:"
            })
        }
    }

    func testRenderConfirmAndMessageStates() {
        renderBoth("confirm") {
            ConfirmView(spec: spec(.confirm(oneButton: false)), onResult: { _ in })
        }
        renderBoth("confirm-notok") {
            ConfirmView(
                spec: spec(.confirm(oneButton: false)) { $0.notOKLabel = "Don't Save" },
                onResult: { _ in })
        }
        renderBoth("confirm-one-button") {
            ConfirmView(spec: spec(.confirm(oneButton: true)), onResult: { _ in })
        }
        renderBoth("confirm-error") {
            ConfirmView(
                spec: spec(.confirm(oneButton: false)) { $0.error = "The card was removed." },
                onResult: { _ in })
        }
        renderBoth("message") { MessageView(spec: spec(.message), onResult: { _ in }) }
    }

    // MARK: - Layout invariants

    // A hostile or buggy SETDESC must not push the buttons out of reach.
    func testLongDescriptionKeepsDialogHeightBounded() {
        let pin = renderBoth("pin-long") {
            pinView(spec(.pin) { $0.description = Self.longDescription })
        }
        let confirm = renderBoth("confirm-long") {
            ConfirmView(
                spec: spec(.confirm(oneButton: false)) { $0.description = Self.longDescription },
                onResult: { _ in })
        }
        let message = renderBoth("message-long") {
            MessageView(spec: spec(.message) { $0.description = Self.longDescription },
                        onResult: { _ in })
        }
        XCTAssertLessThan(pin.size.height, 520)
        XCTAssertLessThan(confirm.size.height, 420)
        XCTAssertLessThan(message.size.height, 420)
    }

    func testShortDescriptionIsNotPadded() {
        let short = MountedDialog(MessageView(spec: spec(.message), onResult: { _ in }))
        let long = MountedDialog(
            MessageView(spec: spec(.message) { $0.description = Self.longDescription },
                        onResult: { _ in }))
        XCTAssertLessThan(short.size.height, long.size.height)
        XCTAssertLessThan(short.size.height, 260)
    }

    // The mismatch message must not move anything: the status slot is always
    // reserved when a repeat field exists.
    func testMismatchMessageDoesNotChangeDialogHeight() {
        let repeating = spec(.pin) { $0.repeatPrompt = "Repeat:" }
        let idle = MountedDialog(pinView(repeating, pin: "hunter2"))
        let mismatch = MountedDialog(pinView(repeating, pin: "hunter2", repeatPin: "hunter3"))
        let match = MountedDialog(pinView(repeating, pin: "hunter2", repeatPin: "hunter2"))
        XCTAssertEqual(idle.size.height, mismatch.size.height, accuracy: 0.5)
        XCTAssertEqual(idle.size.height, match.size.height, accuracy: 0.5)
    }

    // MARK: - Secure field

    func testSecureFieldNeverRevealsValueToAccessibility() throws {
        let mounted = MountedDialog(pinView(spec(.pin) { $0.prompt = "PIN:" }))
        let field = try XCTUnwrap(mounted.find(NSSecureTextField.self), "secure field missing")
        field.stringValue = "hunter2-secret"
        let exposed = [
            field.accessibilityValue(),
            field.accessibilityLabel(),
            field.accessibilityHelp(),
            field.accessibilityTitle(),
        ].compactMap { $0 }
        for text in exposed {
            XCTAssertFalse(text.contains("hunter2"), "secure field leaked its value: \(text)")
        }
    }
}

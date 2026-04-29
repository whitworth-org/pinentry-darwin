// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.

import XCTest
@testable import PinentryUI

final class DialogSpecTests: XCTestCase {

    func testResolvedPromptUsesExplicitWhenSet() {
        var spec = DialogSpec(kind: .pin)
        spec.prompt = "PIN:"
        XCTAssertEqual(spec.resolvedPrompt, "PIN:")
    }

    // Regression: gpg-agent occasionally emits `SETPROMPT` with an empty
    // argument before re-issuing one with the real prompt. Earlier we used
    // `prompt ?? defaults.prompt`, which let the empty string through and
    // rendered a blank label. Empty must fall back to defaults.
    func testResolvedPromptEmptyFallsBackToDefaults() {
        var spec = DialogSpec(kind: .pin)
        spec.prompt = ""
        XCTAssertEqual(spec.resolvedPrompt, "Passphrase:")
    }

    func testResolvedPromptNilFallsBackToDefaults() {
        let spec = DialogSpec(kind: .pin)
        XCTAssertEqual(spec.resolvedPrompt, "Passphrase:")
    }

    func testResolvedPromptHonoursLocalisedDefault() {
        var defaults = DialogSpec.DefaultLabels()
        defaults.prompt = "Mot de passe :"
        var spec = DialogSpec(kind: .pin, defaults: defaults)
        spec.prompt = ""
        XCTAssertEqual(spec.resolvedPrompt, "Mot de passe :")
    }

    func testResolvedOKFallback() {
        var spec = DialogSpec(kind: .confirm(oneButton: false))
        XCTAssertEqual(spec.resolvedOK, "OK")
        spec.okLabel = "Continue"
        XCTAssertEqual(spec.resolvedOK, "Continue")
    }

    func testResolvedCancelFallback() {
        var spec = DialogSpec(kind: .confirm(oneButton: false))
        XCTAssertEqual(spec.resolvedCancel, "Cancel")
        spec.cancelLabel = "Abort"
        XCTAssertEqual(spec.resolvedCancel, "Abort")
    }
}

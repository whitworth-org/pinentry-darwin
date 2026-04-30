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

    // MARK: - Keychain affordance gating
    //
    // pinentry-mac shows "Save in Keychain" for any keyinfo mode except
    // 'u' (user). gpg-agent's OPTION allow-external-password-cache is
    // ignored — pinentry-mac doesn't honour it and we must match.

    func testCanSaveToKeychainNormalMode() {
        let ki = DialogSpec.KeyInfo.key(mode: "n", fingerprint: String(repeating: "F", count: 40))
        XCTAssertTrue(DialogSpec.canSaveToKeychain(keyInfo: ki, keychainEnabled: true),
                      "mode 'n' (normal asymmetric key) must allow Save")
    }

    func testCanSaveToKeychainSshMode() {
        let ki = DialogSpec.KeyInfo.key(mode: "s", fingerprint: String(repeating: "F", count: 40))
        XCTAssertTrue(DialogSpec.canSaveToKeychain(keyInfo: ki, keychainEnabled: true),
                      "mode 's' (ssh) must allow Save")
    }

    func testCanSaveToKeychainCardMode() {
        let ki = DialogSpec.KeyInfo.key(mode: "c", fingerprint: String(repeating: "F", count: 40))
        XCTAssertTrue(DialogSpec.canSaveToKeychain(keyInfo: ki, keychainEnabled: true),
                      "mode 'c' (smartcard PIN) must allow Save")
    }

    func testCanSaveToKeychainUserModeBlocked() {
        let ki = DialogSpec.KeyInfo.key(mode: "u", fingerprint: String(repeating: "F", count: 40))
        XCTAssertFalse(DialogSpec.canSaveToKeychain(keyInfo: ki, keychainEnabled: true),
                       "mode 'u' (user-managed) must block Save — matches pinentry-mac")
    }

    func testCanSaveToKeychainNoKeyInfoBlocked() {
        XCTAssertFalse(DialogSpec.canSaveToKeychain(keyInfo: nil, keychainEnabled: true),
                       "no SETKEYINFO means no fingerprint to key against")
    }

    func testCanSaveToKeychainPrefDisabledBlocked() {
        let ki = DialogSpec.KeyInfo.key(mode: "n", fingerprint: String(repeating: "F", count: 40))
        XCTAssertFalse(DialogSpec.canSaveToKeychain(keyInfo: ki, keychainEnabled: false),
                       "user disabled keychain in prefs blocks Save")
    }
}

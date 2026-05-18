// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// HardenedSecureFieldTests — verify the field-level and field-editor-
// level hardening applied by `HardenedFieldConfig`. We do NOT exercise
// the full NSViewRepresentable lifecycle here (that would require a
// running NSWindow with a connected display, which is unreliable in
// `swift test`) — we instead apply the configuration directly to an
// NSTextField / NSTextView and assert every flag is in its hardened
// state.

import AppKit
import XCTest
@testable import PinentryUI

@MainActor
final class HardenedSecureFieldTests: XCTestCase {

    // MARK: NSTextField-level hardening

    func testApplyConfiguresNSTextFieldForSingleLineEntry() {
        let field = NSTextField()
        HardenedFieldConfig.apply(to: field)

        XCTAssertTrue(field.isBezeled)
        XCTAssertEqual(field.bezelStyle, .roundedBezel)
        XCTAssertTrue(field.isEditable)
        XCTAssertTrue(field.isSelectable)
        XCTAssertTrue(field.usesSingleLineMode)
        XCTAssertEqual(field.lineBreakMode, .byTruncatingTail)
    }

    func testApplyDisablesCharacterPickerTouchBarItem() {
        let field = NSTextField()
        HardenedFieldConfig.apply(to: field)
        XCTAssertFalse(field.allowsCharacterPickerTouchBarItem,
                       "character-picker Touch Bar item must be off")
    }

    func testApplyAlsoConfiguresNSSecureTextField() {
        // NSSecureTextField inherits from NSTextField; the same
        // configuration must work on the secure subclass.
        let field = NSSecureTextField()
        HardenedFieldConfig.apply(to: field)
        XCTAssertTrue(field.usesSingleLineMode)
        XCTAssertFalse(field.allowsCharacterPickerTouchBarItem)
    }

    // MARK: NSTextView (field-editor) hardening

    func testApplyToEditorDisablesAutoSubstitutions() {
        let editor = NSTextView()
        // Pre-flip to ensure we're actually flipping (not just observing
        // the AppKit defaults).
        editor.isAutomaticQuoteSubstitutionEnabled    = true
        editor.isAutomaticDashSubstitutionEnabled     = true
        editor.isAutomaticTextReplacementEnabled      = true
        editor.isAutomaticSpellingCorrectionEnabled   = true
        editor.isAutomaticDataDetectionEnabled        = true
        editor.isAutomaticLinkDetectionEnabled        = true
        editor.smartInsertDeleteEnabled               = true

        HardenedFieldConfig.apply(toEditor: editor)

        XCTAssertFalse(editor.isAutomaticQuoteSubstitutionEnabled)
        XCTAssertFalse(editor.isAutomaticDashSubstitutionEnabled)
        XCTAssertFalse(editor.isAutomaticTextReplacementEnabled)
        XCTAssertFalse(editor.isAutomaticSpellingCorrectionEnabled)
        XCTAssertFalse(editor.isAutomaticDataDetectionEnabled)
        XCTAssertFalse(editor.isAutomaticLinkDetectionEnabled)
        XCTAssertFalse(editor.smartInsertDeleteEnabled)
    }

    func testApplyToEditorDisablesSpellAndGrammarChecking() {
        let editor = NSTextView()
        editor.isContinuousSpellCheckingEnabled = true
        editor.isGrammarCheckingEnabled         = true

        HardenedFieldConfig.apply(toEditor: editor)

        XCTAssertFalse(editor.isContinuousSpellCheckingEnabled)
        XCTAssertFalse(editor.isGrammarCheckingEnabled)
    }

    func testApplyToEditorDisablesCharacterPickerAndUndo() {
        let editor = NSTextView()
        editor.allowsCharacterPickerTouchBarItem = true
        editor.allowsUndo                        = true

        HardenedFieldConfig.apply(toEditor: editor)

        XCTAssertFalse(editor.allowsCharacterPickerTouchBarItem)
        XCTAssertFalse(editor.allowsUndo,
                       "field-editor undo manager must be off so partial " +
                       "passphrase keystrokes are not retained in memory")
    }

    // MARK: Subclasses

    func testHardenedNSSecureTextFieldRoundTripsStringValue() {
        let field = HardenedNSSecureTextField()
        field.stringValue = "hunter2"
        XCTAssertEqual(field.stringValue, "hunter2")
    }

    func testHardenedNSTextFieldRoundTripsStringValue() {
        let field = HardenedNSTextField()
        field.stringValue = "visible-passphrase"
        XCTAssertEqual(field.stringValue, "visible-passphrase")
    }
}

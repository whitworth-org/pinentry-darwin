// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// HardenedSecureField / HardenedTextField — AppKit-backed SwiftUI text
// inputs with every passphrase-hostile auto-mangling behaviour explicitly
// off.
//
// Why bypass SwiftUI's native SecureField/TextField:
//   SwiftUI on macOS exposes only a small subset of AppKit's text-input
//   knobs. In particular it does NOT let us disable smart-quote
//   substitution, dash substitution, automatic spell correction, the
//   character-picker Touch Bar item, or the field editor's undo stack —
//   any of which can either visually corrupt a typed passphrase or
//   retain a recoverable copy of it in process memory.
//
// What we configure:
//   - On the NSTextField itself: `allowsCharacterPickerTouchBarItem`,
//     visual bezel, single-line constraint.
//   - On the field-editor NSTextView (loaded lazily when the field
//     becomes first responder): `isAutomaticQuoteSubstitutionEnabled`,
//     `isAutomaticDashSubstitutionEnabled`,
//     `isAutomaticTextReplacementEnabled`,
//     `isAutomaticSpellingCorrectionEnabled`,
//     `isAutomaticDataDetectionEnabled`,
//     `isAutomaticLinkDetectionEnabled`,
//     `isContinuousSpellCheckingEnabled`,
//     `isGrammarCheckingEnabled`,
//     `smartInsertDeleteEnabled`,
//     `allowsCharacterPickerTouchBarItem`,
//     `allowsUndo` (prevents the field editor's undo manager from
//     retaining historical passphrase fragments in memory).
//
// What we deliberately don't try to do:
//   - We don't override `validateMenuItem(_:)` to strip Cut/Copy/Paste.
//     SwiftUI's NSSecureTextField already refuses to vend passphrase
//     bytes via Copy (the field returns "•••••" not the underlying
//     string); Paste remains useful and PasteboardGuard handles the
//     residue. Cut behaves the same as Copy on a SecureTextField.
//   - We don't disable system IME globally. `SecureInput` (Carbon
//     `EnableSecureEventInput`) already does that for the dialog's
//     lifetime and is the right layer for that control.

import AppKit
import SwiftUI

// MARK: - SwiftUI wrappers

/// SwiftUI wrapper around a hardened `NSSecureTextField`. Drop-in
/// replacement for SwiftUI's `SecureField`, with all field-editor
/// auto-substitutions disabled.
@MainActor
public struct HardenedSecureField: NSViewRepresentable {

    @Binding public var text: String
    public let becomesFirstResponderOnAppear: Bool
    public let onSubmit: () -> Void

    public init(
        text: Binding<String>,
        becomesFirstResponderOnAppear: Bool = false,
        onSubmit: @escaping () -> Void = {}
    ) {
        self._text = text
        self.becomesFirstResponderOnAppear = becomesFirstResponderOnAppear
        self.onSubmit = onSubmit
    }

    public func makeCoordinator() -> HardenedFieldCoordinator {
        HardenedFieldCoordinator(text: $text, onSubmit: onSubmit)
    }

    public func makeNSView(context: Context) -> NSSecureTextField {
        let field = HardenedNSSecureTextField()
        HardenedFieldConfig.apply(to: field)
        field.delegate = context.coordinator
        field.stringValue = text
        if becomesFirstResponderOnAppear {
            // Defer to the next runloop tick so the window has had a
            // chance to install us before we ask to become key.
            DispatchQueue.main.async { [weak field] in
                field?.window?.makeFirstResponder(field)
            }
        }
        return field
    }

    public func updateNSView(_ field: NSSecureTextField, context: Context) {
        // Keep the field's stringValue in sync with the binding only
        // when they diverge; touching `stringValue` resets the
        // insertion-point and the autocompletion candidate strip.
        if field.stringValue != text {
            field.stringValue = text
        }
        context.coordinator.update(text: $text, onSubmit: onSubmit)
    }
}

/// SwiftUI wrapper around a hardened `NSTextField` for the "Show typing"
/// path. Same auto-substitution hardening as `HardenedSecureField`; the
/// passphrase is visible on screen as the user typed it, but the field
/// editor will not silently mutate it.
@MainActor
public struct HardenedTextField: NSViewRepresentable {

    @Binding public var text: String
    public let becomesFirstResponderOnAppear: Bool
    public let onSubmit: () -> Void

    public init(
        text: Binding<String>,
        becomesFirstResponderOnAppear: Bool = false,
        onSubmit: @escaping () -> Void = {}
    ) {
        self._text = text
        self.becomesFirstResponderOnAppear = becomesFirstResponderOnAppear
        self.onSubmit = onSubmit
    }

    public func makeCoordinator() -> HardenedFieldCoordinator {
        HardenedFieldCoordinator(text: $text, onSubmit: onSubmit)
    }

    public func makeNSView(context: Context) -> NSTextField {
        let field = HardenedNSTextField()
        HardenedFieldConfig.apply(to: field)
        field.delegate = context.coordinator
        field.stringValue = text
        if becomesFirstResponderOnAppear {
            DispatchQueue.main.async { [weak field] in
                field?.window?.makeFirstResponder(field)
            }
        }
        return field
    }

    public func updateNSView(_ field: NSTextField, context: Context) {
        if field.stringValue != text {
            field.stringValue = text
        }
        context.coordinator.update(text: $text, onSubmit: onSubmit)
    }
}

// MARK: - Shared coordinator

@MainActor
public final class HardenedFieldCoordinator: NSObject, NSTextFieldDelegate {

    private var text: Binding<String>
    private var onSubmit: () -> Void

    init(text: Binding<String>, onSubmit: @escaping () -> Void) {
        self.text = text
        self.onSubmit = onSubmit
    }

    /// Re-bind on each SwiftUI update so closures captured at init time
    /// don't reference a stale `text` binding when the parent re-renders.
    func update(text: Binding<String>, onSubmit: @escaping () -> Void) {
        self.text = text
        self.onSubmit = onSubmit
    }

    public func controlTextDidChange(_ obj: Notification) {
        guard let field = obj.object as? NSTextField else { return }
        text.wrappedValue = field.stringValue
    }

    public func control(
        _ control: NSControl,
        textView: NSTextView,
        doCommandBy commandSelector: Selector
    ) -> Bool {
        if commandSelector == #selector(NSResponder.insertNewline(_:)) {
            onSubmit()
            return true
        }
        return false
    }
}

// MARK: - Hardened NSTextField subclasses

/// `NSSecureTextField` that disables the field-editor's auto-mangling
/// flags every time it becomes first responder. We re-apply on
/// `becomeFirstResponder` because the field editor is shared across
/// fields in the same window, so a sibling text field may have re-
/// enabled the flags between focus changes.
final class HardenedNSSecureTextField: NSSecureTextField {
    override func becomeFirstResponder() -> Bool {
        let ok = super.becomeFirstResponder()
        if ok, let editor = currentEditor() as? NSTextView {
            HardenedFieldConfig.apply(toEditor: editor)
        }
        return ok
    }
}

final class HardenedNSTextField: NSTextField {
    override func becomeFirstResponder() -> Bool {
        let ok = super.becomeFirstResponder()
        if ok, let editor = currentEditor() as? NSTextView {
            HardenedFieldConfig.apply(toEditor: editor)
        }
        return ok
    }
}

// MARK: - Shared configuration

@MainActor
enum HardenedFieldConfig {

    /// Apply NSTextField-level hardening. Idempotent.
    static func apply(to field: NSTextField) {
        field.isBezeled = true
        field.bezelStyle = .roundedBezel
        field.isEditable = true
        field.isSelectable = true
        field.usesSingleLineMode = true
        field.lineBreakMode = .byTruncatingTail
        field.allowsCharacterPickerTouchBarItem = false
        field.placeholderString = ""
        // System font matches the SwiftUI defaults so the visual size of
        // the field matches the rest of the dialog.
        field.font = .systemFont(ofSize: NSFont.systemFontSize)
    }

    /// Apply NSTextView-level hardening to the shared field editor. The
    /// flags below are the union of everything macOS will do to mangle
    /// typed text "helpfully" and the operations that retain copies of
    /// it (`allowsUndo`). Every one is explicitly off.
    static func apply(toEditor editor: NSTextView) {
        editor.isAutomaticQuoteSubstitutionEnabled    = false
        editor.isAutomaticDashSubstitutionEnabled     = false
        editor.isAutomaticTextReplacementEnabled      = false
        editor.isAutomaticSpellingCorrectionEnabled   = false
        editor.isAutomaticDataDetectionEnabled        = false
        editor.isAutomaticLinkDetectionEnabled        = false
        editor.isContinuousSpellCheckingEnabled       = false
        editor.isGrammarCheckingEnabled               = false
        editor.smartInsertDeleteEnabled               = false
        editor.allowsCharacterPickerTouchBarItem      = false
        // Prevent the field editor's undo manager from retaining
        // historical passphrase fragments in memory after submit.
        editor.allowsUndo = false
    }
}

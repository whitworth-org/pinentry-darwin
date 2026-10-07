// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// PinView.swift — the SwiftUI body for `GETPIN`.
//
// Layout: the shared DialogScaffold (icon left, content right). Prompt labels
// and fields sit in a Grid so labels of any length stay aligned; the option
// checkboxes, SETERROR and the repeat-status line align under the fields.
//
// See PinViewModel for the SwiftUI String / SecureBytes residue caveat.

import Observation
public import SwiftUI
import KeychainStore

public struct PinView: View {
    public let spec: DialogSpec

    /// Whether to enable Carbon's secure keyboard entry while this view
    /// is on screen. Driven by UISettings.secureKeyboardEntry; the
    /// coordinator threads it through so the view doesn't need to
    /// observe UISettingsStore itself.
    public let secureKeyboardEntry: Bool

    /// Whether to wipe `NSPasteboard.general` on submit when the change
    /// count advanced during the dialog's lifetime (i.e. the user
    /// paste-filled the passphrase). Driven by
    /// UISettings.clearPasteboardOnSubmit.
    public let clearPasteboardOnSubmit: Bool

    @Bindable public var model: PinViewModel

    /// SwiftUI text-storage scratch. We *write* into this on every change
    /// to keep the field rendering, but never *read* it for any value
    /// other than mirroring into the view-model. The authoritative
    /// passphrase lives in `model.pin`.
    @State private var pinText: String = ""
    @State private var repeatText: String = ""

    /// Set when Return is pressed while OK is disabled, so a too-short repeat
    /// is reported as a mismatch instead of leaving Return silently ignored.
    @State private var submitAttempted: Bool = false

    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    /// True between our `enable()` and the matching `disable()`. Tracked
    /// per-instance so a view that's torn down without `.onDisappear`
    /// firing (rare but possible under SwiftUI rebuilds) doesn't leave
    /// SKE stuck on; we still rely on process-termination cleanup as
    /// the ultimate backstop.
    @State private var skeActive: Bool = false

    /// `NSPasteboard.general.changeCount` snapshot taken on appear. We
    /// compare against this on submit to detect that a paste (or any
    /// other pasteboard write) happened during the dialog's lifetime
    /// and clear the pasteboard if the user has opted in. -1 sentinel
    /// means "not snapshotted yet" so we never clear without a baseline.
    @State private var pasteboardBaseline: Int = -1

    public init(
        spec: DialogSpec,
        model: PinViewModel,
        secureKeyboardEntry: Bool = true,
        clearPasteboardOnSubmit: Bool = true
    ) {
        self.spec = spec
        self.model = model
        self.secureKeyboardEntry = secureKeyboardEntry
        self.clearPasteboardOnSubmit = clearPasteboardOnSubmit
    }

    public var body: some View {
        DialogScaffold(symbol: "lock.shield.fill") {
            DialogTextBlock(spec: spec)
            fieldGrid
        } footer: {
            DialogButtonRow(
                spec: spec,
                oneButton: false,
                okEnabled: model.canSubmit,
                isBusy: model.isSubmitting
            ) { role in
                switch role {
                case .ok: handleSubmit()
                // NotOK on a GETPIN is unusual but the protocol permits it.
                // Treated as a non-confirmation result.
                case .cancel, .notOK: model.cancel()
                }
            }
        }
        .onAppear(perform: engageProtections)
        .onDisappear(perform: releaseProtections)
        .onChange(of: fieldStatus) { _, status in
            if let message = status.message(for: spec) {
                AccessibilityNotification.Announcement(message).post()
            }
        }
    }

    /// Engage secure keyboard entry as the very first thing, before the field
    /// gets focus, so no keystroke can land in an unprotected window. Skipped
    /// if the user disabled it in Settings.
    private func engageProtections() {
        if secureKeyboardEntry, SecureInput.enable() {
            skeActive = true
        }

        // Snapshot the pasteboard change-count so we can detect a paste-fill
        // on submit without ever inspecting clipboard contents.
        pasteboardBaseline = PasteboardGuard.snapshot()

        // The pin field carries `becomesFirstResponderOnAppear: true` so AppKit
        // grabs focus the moment it mounts; no SwiftUI FocusState plumbing.
    }

    private func releaseProtections() {
        // Balance our SKE enable. Process termination would clean this up
        // automatically (kernel-level refcount drops at exit), but disabling
        // promptly removes the menu-bar lock badge while the process is still
        // doing post-dialog work.
        if skeActive {
            SecureInput.disable()
            skeActive = false
        }

        // L-3(b): clear the SwiftUI text-storage scratch on every resolution
        // path. The window always closes on resolve (OK, cancel, close,
        // timeout) which fires onDisappear, so this is the single choke point
        // that covers all four. This only shortens the residue window: the
        // prior per-keystroke String copies SwiftUI made are already
        // unwipeable; that residual is documented in PinViewModel and accepted
        // for v1.0.0.
        pinText = ""
        repeatText = ""

        // L-5: clear the pasteboard on the abandonment paths too. Cancel,
        // red-X close, and timeout never route through handleSubmit(), so a
        // paste-filled passphrase would otherwise linger on NSPasteboard.general
        // after the dialog is gone. Gated on the SAME clearPasteboardOnSubmit
        // opt-in and the same changeCount baseline as the submit path;
        // idempotent, so the OK path (which already cleared in handleSubmit) is
        // unharmed. We never read pasteboard contents, only whether the count
        // advanced during the dialog's lifetime.
        PasteboardGuard.clearIfAdvanced(
            since: pasteboardBaseline,
            enabled: clearPasteboardOnSubmit
        )
    }

    // MARK: - Field grid

    private var fieldStatus: FieldStatus {
        FieldStatus.evaluate(
            pinLength: model.pinLength,
            repeatLength: model.repeatLength,
            pinsMatch: model.pinsMatch,
            truncated: model.pinTruncated || model.repeatTruncated,
            submitAttempted: submitAttempted
        )
    }

    /// Prompt labels in one column, fields in the other. Rows without a label
    /// reserve the label column so their content lines up under the fields.
    private var fieldGrid: some View {
        VStack(alignment: .leading, spacing: Theme.smallPadding) {
            if let error = spec.error.nonEmpty {
                indentedRow { StatusLine(tone: .error, text: error) }
            }
            fieldRow(
                label: spec.resolvedPrompt,
                binding: $pinText,
                hint: spec.error.nonEmpty,
                isPinRow: true
            )
            if let repeatPrompt = spec.repeatPrompt {
                fieldRow(
                    label: repeatPrompt,
                    binding: $repeatText,
                    hint: "Enter the passphrase again.",
                    isPinRow: false
                )
            }
            if spec.repeatPrompt != nil || fieldStatus != .hidden {
                indentedRow { statusSlot }
            }
            indentedRow { optionsColumn }
        }
    }

    /// Invisible stack of every label, so each row's label cell is as wide as
    /// the widest one without a fixed column width.
    private var labelSizer: some View {
        let labels = [spec.resolvedPrompt] + (spec.repeatPrompt.map { [$0] } ?? [])
        return ZStack(alignment: .trailing) {
            ForEach(Array(labels.enumerated()), id: \.offset) { _, label in
                Text(verbatim: label).font(Theme.bodyFont)
            }
        }
        .hidden()
        .accessibilityHidden(true)
    }

    /// The label sizer also gives the row a one-line minimum height, so a
    /// status line appearing or disappearing never moves the rows below it.
    private func indentedRow<Content: View>(
        @ViewBuilder _ content: () -> Content
    ) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: Theme.smallPadding) {
            labelSizer
            content()
            Spacer(minLength: 0)
        }
    }

    private func fieldRow(
        label: String,
        binding: Binding<String>,
        hint: String?,
        isPinRow: Bool
    ) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: Theme.smallPadding) {
            ZStack(alignment: .trailing) {
                labelSizer
                Text(verbatim: label)
                    .font(Theme.bodyFont)
                    .accessibilityHidden(true)
            }

            pinField(
                binding: binding,
                onChange: { value in
                    if isPinRow { model.setPin(from: value) } else { model.setRepeat(from: value) }
                },
                accessibilityLabel: label,
                accessibilityHint: hint,
                isPinRow: isPinRow
            )
        }
    }

    private var statusSlot: some View {
        Group {
            if let message = fieldStatus.message(for: spec) {
                StatusLine(tone: fieldStatus.tone, text: message)
                    .transition(.opacity)
            }
        }
        .animation(
            reduceMotion ? nil : .easeOut(duration: DialogStyle.statusFadeDuration),
            value: fieldStatus
        )
    }

    /// Show typing toggle, optionally joined by the Save in Keychain checkbox.
    ///
    /// KC-2 / FV-1: when the data-protection keychain has rejected this
    /// process for missing entitlement (typical for ad-hoc-signed builds:
    /// `swift run`, locally re-signed, third-party rebuild), the Save
    /// affordance is disabled and a caption explains why. We read
    /// `KeychainStore.degradedPostureObserved` rather than reaching into a
    /// global app-state mediator: the flag is a process-wide monotonic Bool
    /// that flips at most once per process lifetime.
    private var optionsColumn: some View {
        let degraded = KeychainStore.degradedPostureObserved
        return VStack(alignment: .leading, spacing: Theme.smallPadding) {
            HStack(spacing: Theme.blockPadding) {
                Toggle("Show typing", isOn: $model.showTyping)
                if spec.allowKeychainSave {
                    Toggle("Save in Keychain", isOn: $model.saveToKeychain)
                        .disabled(degraded)
                }
            }
            .toggleStyle(.checkbox)
            .font(Theme.bodyFont)

            if spec.allowKeychainSave && degraded {
                StatusLine(
                    tone: .info,
                    text: "Can't save to Keychain: this build is signed ad hoc."
                )
            }
        }
    }

    // MARK: - Field

    /// HardenedSecureField (or HardenedTextField when revealed via the
    /// Show typing checkbox): both AppKit-backed wrappers with every
    /// auto-substitution / spell-correction / character-picker behaviour
    /// explicitly off and the field editor's undo manager disabled.
    /// See `HardenedSecureField.swift` for the full hardening surface.
    ///
    /// We intercept binding writes via a wrapper Binding so the model's
    /// `setPin(from:)` fires *synchronously* on every keystroke. Observing
    /// `.onChange(of: binding.wrappedValue)` instead debounced or dropped
    /// SecureField writes on macOS Sequoia (OK stayed disabled until Show
    /// typing was toggled).
    ///
    /// Accessibility: the label is the prompt; no accessibility *value* is ever
    /// set, so the secure field's own masked value is all VoiceOver can read.
    ///
    /// Focus: the pin row auto-focuses on first appear and on any Show typing
    /// rebuild. The repeat row never auto-focuses; the user tabs / clicks into
    /// it. AppKit's automatic nextKeyView chain handles tab navigation.
    @ViewBuilder
    private func pinField(
        binding: Binding<String>,
        onChange: @escaping (String) -> Void,
        accessibilityLabel: String,
        accessibilityHint: String?,
        isPinRow: Bool
    ) -> some View {
        let intercepted = Binding<String>(
            get: { binding.wrappedValue },
            set: { newValue in
                binding.wrappedValue = newValue
                onChange(newValue)
            }
        )
        if model.showTyping {
            HardenedTextField(
                text: intercepted,
                becomesFirstResponderOnAppear: isPinRow,
                onSubmit: { handleSubmit() }
            )
            .frame(maxWidth: .infinity)
            .accessibilityLabel(Text(verbatim: accessibilityLabel))
            .accessibilityHint(Text(verbatim: accessibilityHint ?? ""))
        } else {
            HardenedSecureField(
                text: intercepted,
                becomesFirstResponderOnAppear: isPinRow,
                onSubmit: { handleSubmit() }
            )
            .frame(maxWidth: .infinity)
            .accessibilityLabel(Text(verbatim: accessibilityLabel))
            .accessibilityHint(Text(verbatim: accessibilityHint ?? ""))
        }
    }

    /// All paths that submit the dialog go through this single method:
    /// OK button click, Return-key shortcut on the OK button, and the
    /// HardenedSecureField's own Return-key handler. We snapshot-and-
    /// clear the system pasteboard here so any paste-fill leaves no
    /// residue before the model resolves.
    private func handleSubmit() {
        guard !model.isSubmitting else { return }
        guard model.canSubmit else {
            submitAttempted = true
            return
        }
        PasteboardGuard.clearIfAdvanced(
            since: pasteboardBaseline,
            enabled: clearPasteboardOnSubmit
        )
        model.submit()
    }
}

// MARK: - Field status

/// What the status line under the fields says. A pure function of the
/// model's lengths and flags, so the rules are testable without a view.
enum FieldStatus: Equatable {
    case hidden, mismatch, match, tooLong

    /// - A repeat that is still shorter than the passphrase may yet match, so
    ///   it stays quiet while the user types; an eager error on the first
    ///   keystroke would be wrong and, to VoiceOver, noisy.
    /// - Once the repeat is as long as the passphrase, or the user pressed
    ///   Return, a difference is a mismatch.
    static func evaluate(
        pinLength: Int,
        repeatLength: Int,
        pinsMatch: Bool,
        truncated: Bool,
        submitAttempted: Bool
    ) -> FieldStatus {
        if truncated { return .tooLong }
        guard repeatLength > 0 else { return .hidden }
        if pinsMatch { return .match }
        return repeatLength >= pinLength || submitAttempted ? .mismatch : .hidden
    }

    /// Text for the status line. gpg-agent's SETREPEATERROR / SETREPEATOK win
    /// over the built-in wording; a match without SETREPEATOK says nothing.
    func message(for spec: DialogSpec) -> String? {
        switch self {
        case .hidden: nil
        case .mismatch: spec.repeatError.nonEmpty ?? "Passphrases do not match."
        case .match: spec.repeatOK.nonEmpty
        case .tooLong: "Passphrase is too long."
        }
    }

    var tone: StatusLine.Tone {
        switch self {
        case .match: .success
        case .hidden, .mismatch, .tooLong: .error
        }
    }
}

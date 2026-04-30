// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// PinView.swift — the SwiftUI body for `GETPIN`. See PinViewModel for the
// String/SecureBytes-residue caveat.
//
// Layout direction: refined minimalism with security-craft sensibility
// (see Theme.swift). One iconographic anchor at the top, strict
// typographic hierarchy, the OK button is the only saturated control,
// and a single 220ms ease-out fade-and-rise on appear. The "Show
// typing" affordance lives as an eye/eye.slash button inside each
// passphrase field — the 1Password-style placement that keeps the
// chrome density honest.

import Observation
import SwiftUI
import SecureMemory

public struct PinView: View {
    public let spec: DialogSpec

    /// Whether to enable Carbon's secure keyboard entry while this view
    /// is on screen. Driven by UISettings.secureKeyboardEntry; the
    /// coordinator threads it through so the view doesn't need to
    /// observe UISettingsStore itself.
    public let secureKeyboardEntry: Bool

    @Bindable public var model: PinViewModel

    /// SwiftUI text-storage scratch. We *write* into this on every change
    /// to keep the field rendering, but never *read* it for any value
    /// other than mirroring into the view-model. The authoritative
    /// passphrase lives in `model.pin`.
    @State private var pinText: String = ""
    @State private var repeatText: String = ""

    /// Drives the SecureField↔TextField swap inside `pinField`. Replaces
    /// the old `Toggle("Show typing")` checkbox.
    @State private var revealTyping: Bool = false

    /// Drives the entrance animation (alpha 0→1, translateY 8→0).
    @State private var appeared: Bool = false

    /// True between our `enable()` and the matching `disable()`. Tracked
    /// per-instance so a view that's torn down without `.onDisappear`
    /// firing (rare but possible under SwiftUI rebuilds) doesn't leave
    /// SKE stuck on; we still rely on process-termination cleanup as
    /// the ultimate backstop.
    @State private var skeActive: Bool = false

    @FocusState private var focusedField: PinField?
    private enum PinField: Hashable { case pin, repeatPin }

    public init(spec: DialogSpec, model: PinViewModel, secureKeyboardEntry: Bool = true) {
        self.spec = spec
        self.model = model
        self.secureKeyboardEntry = secureKeyboardEntry
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: Theme.blockPadding) {
            headerBlock
            inputBlock
            optionsBlock
            buttonRow
        }
        .padding(.horizontal, Theme.largePadding)
        .padding(.vertical, Theme.blockPadding)
        .frame(maxWidth: .infinity, alignment: .leading)
        .opacity(appeared ? 1 : 0)
        .offset(y: appeared ? 0 : Theme.entranceTranslate)
        .onAppear {
            // Engage secure keyboard entry as the very first thing —
            // before the field gets focus, before the animation runs —
            // so no keystroke can land in an unprotected window. Skipped
            // if the user disabled it in Settings.
            if secureKeyboardEntry, SecureInput.enable() {
                skeActive = true
            }

            // Initialize showTyping from the model (settings preference)
            // and seed focus to the first input.
            revealTyping = model.showTyping
            withAnimation(.easeOut(duration: Theme.entranceDuration)) {
                appeared = true
            }
            // Focus after a tick so the entrance animation has begun and
            // SecureField has its responder chain set up.
            Task { @MainActor in
                try? await Task.sleep(nanoseconds: 60_000_000)
                focusedField = .pin
            }
        }
        .onDisappear {
            // Balance our SKE enable. Process termination would clean
            // this up automatically (kernel-level refcount drops at
            // exit), but disabling promptly removes the menu-bar lock
            // badge while the process is still doing post-dialog work.
            if skeActive {
                SecureInput.disable()
                skeActive = false
            }
        }
        .onChange(of: revealTyping) { _, newValue in
            // Mirror to the model so the Settings preference flows out
            // through the same observable surface.
            model.showTyping = newValue
        }
    }

    // MARK: - Sub-blocks

    /// Top: SF Symbol anchor + title + description + (optional) error +
    /// (optional) key-info fingerprint, separated from the input cluster
    /// by a hairline divider.
    @ViewBuilder
    private var headerBlock: some View {
        VStack(alignment: .leading, spacing: Theme.mediumPadding) {

            // SF Symbol anchor — gives the dialog instant identity.
            Image(systemName: "lock.shield.fill")
                .font(.system(size: Theme.headerIconSize, weight: .semibold))
                .foregroundStyle(Theme.accent)
                .accessibilityHidden(true)

            // SETERROR text, if any. Lives above the title because it's
            // the most urgent thing on screen when present.
            if let err = spec.error, !err.isEmpty {
                Text(err)
                    .font(Theme.bodyFont)
                    .foregroundStyle(Theme.errorText)
                    .fixedSize(horizontal: false, vertical: true)
            }

            if let title = spec.title, !title.isEmpty {
                Text(title)
                    .font(Theme.titleFont)
                    .foregroundStyle(Color.primary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            if let desc = spec.description, !desc.isEmpty {
                Text(desc)
                    .font(Theme.bodyFont)
                    .foregroundStyle(Color.primary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            if case let .key(mode, fpr) = spec.keyInfo {
                Text("\(String(mode))/\(fpr)")
                    .font(Theme.monospacedFont)
                    .foregroundStyle(Color.secondary)
                    .textSelection(.enabled)
                    .accessibilityLabel(Text("Key fingerprint \(fpr)"))
            }

            Divider()
                .overlay(Theme.hairline)
        }
    }

    /// Middle: prompt label, input field with in-field eye toggle,
    /// optional repeat field, optional mismatch hint.
    @ViewBuilder
    private var inputBlock: some View {
        VStack(alignment: .leading, spacing: Theme.smallPadding) {
            Text(spec.resolvedPrompt)
                .font(Theme.bodyFont)
                .foregroundStyle(Color.primary)

            pinField(
                binding: $pinText,
                onChange: { model.setPin(from: $0) },
                accessibilityLabel: spec.resolvedPrompt,
                focus: .pin
            )

            if let repeatPrompt = spec.repeatPrompt {
                Text(repeatPrompt)
                    .font(Theme.bodyFont)
                    .foregroundStyle(Color.primary)
                    .padding(.top, Theme.smallPadding)

                pinField(
                    binding: $repeatText,
                    onChange: { model.setRepeat(from: $0) },
                    accessibilityLabel: repeatPrompt,
                    focus: .repeatPin
                )

                if !model.pinsMatch && model.repeatLength > 0 {
                    Text(spec.repeatError ?? "Passphrases do not match.")
                        .font(Theme.captionFont)
                        .foregroundStyle(Theme.errorText)
                        .transition(.opacity)
                }
            }
        }
    }

    /// "Save in Keychain" toggle (when SETKEYINFO + allow-cache OPTION).
    /// Renders nothing when the dialog has no Keychain affordance.
    @ViewBuilder
    private var optionsBlock: some View {
        if spec.allowKeychainSave {
            Toggle("Save in Keychain", isOn: $model.saveToKeychain)
                .toggleStyle(.checkbox)
                .font(Theme.bodyFont)
        }
    }

    /// Bottom: Cancel / [NotOK] / OK, right-aligned. OK is the only
    /// saturated control in the dialog (`.borderedProminent`) and is
    /// disabled until canSubmit.
    @ViewBuilder
    private var buttonRow: some View {
        HStack(spacing: Theme.smallPadding) {
            Spacer()
            Button(spec.resolvedCancel) {
                model.cancel()
            }
            .keyboardShortcut(.cancelAction)
            .controlSize(.large)

            if let notOK = spec.notOKLabel, !notOK.isEmpty {
                Button(notOK) {
                    // NotOK on a GETPIN is unusual but the protocol
                    // permits it. Treated as a non-confirmation result.
                    // The coordinator translates it to ERR NOT_CONFIRMED.
                    model.cancel()
                }
                .controlSize(.large)
            }

            Button {
                model.submit()
            } label: {
                if model.isSubmitting {
                    HStack(spacing: 6) {
                        ProgressView()
                            .controlSize(.small)
                            .progressViewStyle(.circular)
                        Text(spec.resolvedOK)
                    }
                } else {
                    Text(spec.resolvedOK)
                }
            }
            .keyboardShortcut(.defaultAction)
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .disabled(!model.canSubmit || model.isSubmitting)
        }
    }

    // MARK: - In-field eye toggle

    /// A SecureField/TextField with a trailing eye button rendered as if
    /// it lives INSIDE the same input chrome. We synthesise the rounded
    /// border ourselves rather than fighting `.textFieldStyle(.roundedBorder)`,
    /// because there's no SwiftUI surface to overlay content into a styled
    /// text field on macOS without breaking its layout.
    @ViewBuilder
    private func pinField(
        binding: Binding<String>,
        onChange: @escaping (String) -> Void,
        accessibilityLabel: String,
        focus: PinField
    ) -> some View {
        HStack(spacing: 0) {
            Group {
                if revealTyping {
                    TextField("", text: binding)
                } else {
                    SecureField("", text: binding)
                }
            }
            .textFieldStyle(.plain)
            .font(Theme.inputFont)
            .focused($focusedField, equals: focus)
            .onChange(of: binding.wrappedValue) { _, newValue in
                onChange(newValue)
            }
            .accessibilityLabel(Text(accessibilityLabel))
            .padding(.horizontal, 10)
            .padding(.vertical, 7)

            Button {
                revealTyping.toggle()
            } label: {
                Image(systemName: revealTyping ? "eye.slash" : "eye")
                    .font(.system(size: Theme.inlineIconSize))
                    .foregroundStyle(Color.secondary)
                    .frame(width: 20, height: 20)
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .padding(.trailing, 8)
            .help(revealTyping ? "Hide typing" : "Show typing")
            .accessibilityLabel(Text(revealTyping ? "Hide passphrase" : "Show passphrase"))
        }
        .background(
            RoundedRectangle(cornerRadius: 6, style: .continuous)
                .fill(Color(NSColor.textBackgroundColor))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 6, style: .continuous)
                .strokeBorder(
                    focusedField == focus ? Theme.accent.opacity(0.7) : Theme.hairline,
                    lineWidth: focusedField == focus ? 2 : 1
                )
        )
        .animation(.easeInOut(duration: 0.12), value: focusedField)
    }
}

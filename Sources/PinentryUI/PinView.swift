// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// PinView.swift — the SwiftUI body for `GETPIN`.
//
// Layout direction (post-pinentry-mac-comparison): landscape dialog with
// a large iconographic anchor on the LEFT and the content stack on the
// RIGHT. Mirrors pinentry-mac's information-density (which the user
// validated as "the correct window size") while replacing pinentry-mac's
// dated padlock illustration with a modern SF Symbol and trimming the
// titlebar text. PIN label is inline with the field; Show typing is a
// checkbox indented under the field.
//
// See PinViewModel for the SwiftUI String / SecureBytes residue caveat.

import Observation
import SwiftUI
import KeychainStore
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
        // Two-column landscape layout: hero icon left, content stack right.
        HStack(alignment: .top, spacing: Theme.blockPadding) {
            heroIcon
            contentColumn
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

            // Seed focus synchronously. SwiftUI defers @FocusState
            // application until after the view tree is committed, so
            // setting it in onAppear's body is sufficient.
            focusedField = .pin

            withAnimation(.easeOut(duration: Theme.entranceDuration)) {
                appeared = true
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
    }

    // MARK: - Sub-blocks

    /// Left column: oversized SF Symbol acting as the dialog's identity.
    /// Sized to anchor against the title + multi-line description.
    @ViewBuilder
    private var heroIcon: some View {
        Image(systemName: "lock.shield.fill")
            .font(.system(size: Theme.heroIconSize, weight: .regular))
            .foregroundStyle(Theme.accent)
            .frame(width: Theme.heroIconSize + 8, alignment: .top)
            .accessibilityHidden(true)
    }

    /// Right column: title → description → input row → indented options →
    /// button row. Fills the remaining width.
    @ViewBuilder
    private var contentColumn: some View {
        VStack(alignment: .leading, spacing: Theme.smallPadding) {

            // Title (SETTITLE) — primary heading. Text(verbatim:) is
            // load-bearing: the spec.* strings are attacker-controlled
            // (they come from gpg-agent SET* lines). Plain Text("…")
            // for a runtime String already resolves to the
            // String overload and renders verbatim today, but a
            // future refactor that introduces literal interpolation
            // (e.g. Text("Title: \(title)")) flips to the
            // LocalizedStringKey overload, which interprets markdown
            // and link syntax in the interpolated value. The
            // verbatim init makes the safe contract explicit and
            // unfailable.
            if let title = spec.title, !title.isEmpty {
                Text(verbatim: title)
                    .font(Theme.titleFont)
                    .foregroundStyle(Color.primary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            // SETERROR text, if any. Most urgent thing on screen when
            // present, kept adjacent to the title.
            if let err = spec.error, !err.isEmpty {
                Text(verbatim: err)
                    .font(Theme.bodyFont)
                    .foregroundStyle(Theme.errorText)
                    .fixedSize(horizontal: false, vertical: true)
            }

            // SETDESC text. Multi-line: gpg-agent often packs Number /
            // Holder / Counter rows into a single description for card
            // dialogs, separated by newlines. We render verbatim so the
            // rich smartcard context shows up the same way pinentry-mac
            // displays it.
            if let desc = spec.description, !desc.isEmpty {
                Text(verbatim: desc)
                    .font(Theme.bodyFont)
                    .foregroundStyle(Color.primary)
                    .fixedSize(horizontal: false, vertical: true)
                    .textSelection(.enabled)
            }

            // SETKEYINFO fingerprint, when supplied (non-card flows).
            // Rendered monospace so users can compare hex digit-for-digit.
            if case let .key(mode, fpr) = spec.keyInfo {
                Text(verbatim: formatKeyInfoLabel(mode: mode, fingerprint: fpr))
                    .font(Theme.monospacedFont)
                    .foregroundStyle(Color.secondary)
                    .textSelection(.enabled)
                    .accessibilityLabel(Text(verbatim: "Key fingerprint \(fpr)"))
                    .fixedSize(horizontal: false, vertical: true)
            }

            // PIN input row: prompt label inline with the field. Matches
            // pinentry-mac's "PIN  [____________]" affordance.
            inputRow

            // Optional repeat field (SETREPEAT).
            if let repeatPrompt = spec.repeatPrompt {
                repeatRow(label: repeatPrompt)

                if !model.pinsMatch && model.repeatLength > 0 {
                    Text(verbatim: spec.repeatError ?? "Passphrases do not match.")
                        .font(Theme.captionFont)
                        .foregroundStyle(Theme.errorText)
                        .padding(.leading, Theme.fieldLabelColumnWidth + Theme.smallPadding)
                        .transition(.opacity)
                }
            }

            // Indented options row: Show typing toggle (and optional
            // Save in Keychain checkbox). Indented by the same column
            // width as the field so the controls visually align under
            // the input.
            optionsRow

            Spacer(minLength: 0)

            buttonRow
        }
    }

    /// Format a SETKEYINFO mode + fingerprint into a humane label.
    /// Conventions:
    ///   - 40-hex-char SHA-1 fingerprints render as
    ///     `1EA9 3FE7 B663 8F3C 6B6E  9C5C 2ABD 2764 D9D7 175C`
    ///     (groups of four with a double space at the midpoint — the
    ///     canonical `gpg --fingerprint` output style).
    ///   - Mode 'c' (card-resident key) prefixes "Card key:".
    ///   - Other modes ('n' normal, 's' ssh, 'o' obsolete) render
    ///     without prefix.
    private func formatKeyInfoLabel(mode: Character, fingerprint fpr: String) -> String {
        let hex = fpr.uppercased()
        let formatted: String
        if hex.count == 40, hex.allSatisfy(\.isHexDigit) {
            var pieces: [String] = []
            for chunkStart in stride(from: 0, to: 40, by: 4) {
                let lo = hex.index(hex.startIndex, offsetBy: chunkStart)
                let hi = hex.index(lo, offsetBy: 4)
                pieces.append(String(hex[lo..<hi]))
            }
            formatted = pieces.prefix(5).joined(separator: " ") + "  " + pieces.suffix(5).joined(separator: " ")
        } else {
            formatted = fpr
        }
        switch mode {
        case "c": return "Card key:  \(formatted)"
        case "s": return "SSH key:   \(formatted)"
        default:  return formatted
        }
    }

    /// Prompt label + field on the same row. Label is right-aligned in a
    /// fixed-width column so multi-row labels (e.g. with a repeat field)
    /// stay vertically aligned.
    @ViewBuilder
    private var inputRow: some View {
        HStack(alignment: .firstTextBaseline, spacing: Theme.smallPadding) {
            Text(verbatim: spec.resolvedPrompt)
                .font(Theme.bodyFont)
                .foregroundStyle(Color.primary)
                .frame(width: Theme.fieldLabelColumnWidth, alignment: .trailing)

            pinField(
                binding: $pinText,
                onChange: { model.setPin(from: $0) },
                accessibilityLabel: spec.resolvedPrompt,
                focus: .pin
            )
        }
        .padding(.top, Theme.smallPadding)
    }

    @ViewBuilder
    private func repeatRow(label: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: Theme.smallPadding) {
            Text(verbatim: label)
                .font(Theme.bodyFont)
                .foregroundStyle(Color.primary)
                .frame(width: Theme.fieldLabelColumnWidth, alignment: .trailing)

            pinField(
                binding: $repeatText,
                onChange: { model.setRepeat(from: $0) },
                accessibilityLabel: label,
                focus: .repeatPin
            )
        }
    }

    /// Show typing toggle, indented under the input field. Optionally
    /// joined by the Save in Keychain checkbox when the dialog has a
    /// Keychain affordance.
    ///
    /// KC-2 / FV-1: when the data-protection keychain has rejected this
    /// process for missing entitlement (typical for ad-hoc-signed builds:
    /// `swift run`, locally re-signed, third-party rebuild), the Save
    /// affordance is disabled and a one-line caption explains why. We
    /// read `KeychainStore.degradedPostureObserved` rather than reaching
    /// into a global app-state mediator: the flag is a process-wide
    /// monotonic Bool that flips at most once per process lifetime.
    @ViewBuilder
    private var optionsRow: some View {
        let degraded = KeychainStore.degradedPostureObserved
        VStack(alignment: .leading, spacing: 2) {
            HStack(spacing: Theme.blockPadding) {
                Toggle("Show typing", isOn: $model.showTyping)
                    .toggleStyle(.checkbox)
                    .font(Theme.bodyFont)

                if spec.allowKeychainSave {
                    Toggle("Save in Keychain", isOn: $model.saveToKeychain)
                        .toggleStyle(.checkbox)
                        .font(Theme.bodyFont)
                        .disabled(degraded)
                }
            }
            if spec.allowKeychainSave && degraded {
                Text(verbatim: "Save unavailable — running with degraded keychain posture (ad-hoc signature).")
                    .font(Theme.captionFont)
                    .foregroundStyle(Theme.errorText)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(.leading, Theme.fieldLabelColumnWidth + Theme.smallPadding)
    }

    /// Bottom: Cancel / [NotOK] / OK, right-aligned. OK is the only
    /// saturated control in the dialog and is disabled until canSubmit.
    @ViewBuilder
    private var buttonRow: some View {
        HStack(spacing: Theme.smallPadding) {
            Spacer()
            Button(spec.resolvedCancel) {
                model.cancel()
            }
            .keyboardShortcut(.cancelAction)
            .controlSize(.regular)

            if let notOK = spec.notOKLabel, !notOK.isEmpty {
                Button(notOK) {
                    // NotOK on a GETPIN is unusual but the protocol
                    // permits it. Treated as a non-confirmation result.
                    model.cancel()
                }
                .controlSize(.regular)
            }

            Button {
                model.submit()
            } label: {
                if model.isSubmitting {
                    HStack(spacing: 6) {
                        ProgressView()
                            .controlSize(.small)
                            .progressViewStyle(.circular)
                        Text(verbatim: spec.resolvedOK)
                    }
                } else {
                    Text(verbatim: spec.resolvedOK)
                }
            }
            .keyboardShortcut(.defaultAction)
            .buttonStyle(PrimaryButtonStyle())
            .disabled(!model.canSubmit || model.isSubmitting)
            .opacity(model.canSubmit && !model.isSubmitting ? 1.0 : 0.45)
        }
    }

    // MARK: - Field

    /// SecureField (or TextField when revealed via the Show typing
    /// checkbox) using the canonical macOS rounded-border style for
    /// guaranteed input handling.
    ///
    /// We intercept binding writes via a wrapper Binding so the model's
    /// `setPin(from:)` fires *synchronously* on every keystroke. The
    /// previous implementation observed `.onChange(of: binding.wrappedValue)`
    /// on the enclosing Group, which on macOS Sequoia debounced or
    /// dropped SecureField writes — the symptom was OK staying disabled
    /// until the user toggled Show typing (which re-rendered the field
    /// hierarchy and back-filled the model on rebuild). Wrapping the
    /// binding makes the side-effect deterministic, regardless of which
    /// field type is currently mounted or how SwiftUI batches updates.
    @ViewBuilder
    private func pinField(
        binding: Binding<String>,
        onChange: @escaping (String) -> Void,
        accessibilityLabel: String,
        focus: PinField
    ) -> some View {
        let intercepted = Binding<String>(
            get: { binding.wrappedValue },
            set: { newValue in
                binding.wrappedValue = newValue
                onChange(newValue)
            }
        )
        if model.showTyping {
            TextField("", text: intercepted)
                .textFieldStyle(.roundedBorder)
                .font(Theme.inputFont)
                .focused($focusedField, equals: focus)
                .accessibilityLabel(Text(verbatim: accessibilityLabel))
        } else {
            SecureField("", text: intercepted)
                .textFieldStyle(.roundedBorder)
                .font(Theme.inputFont)
                .focused($focusedField, equals: focus)
                .accessibilityLabel(Text(verbatim: accessibilityLabel))
        }
    }
}

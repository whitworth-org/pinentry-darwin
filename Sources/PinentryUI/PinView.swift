// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// PinView.swift — the SwiftUI body for `GETPIN`. See PinViewModel for the
// String/SecureBytes-residue caveat.

import Observation
import SwiftUI
import SecureMemory

public struct PinView: View {
    public let spec: DialogSpec

    @Bindable public var model: PinViewModel

    /// SwiftUI text-storage scratch. We *write* into this on every change
    /// to keep the field rendering, but never *read* it for any value
    /// other than mirroring into the view-model. The authoritative
    /// passphrase lives in `model.pin`.
    @State private var pinText: String = ""
    @State private var repeatText: String = ""

    public init(spec: DialogSpec, model: PinViewModel) {
        self.spec = spec
        self.model = model
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: Theme.mediumPadding) {

            if let err = spec.error, !err.isEmpty {
                Text(err)
                    .font(Theme.bodyFont)
                    .foregroundStyle(Theme.errorText)
                    .fixedSize(horizontal: false, vertical: true)
            }

            if let title = spec.title, !title.isEmpty {
                Text(title)
                    .font(Theme.titleFont)
                    .fontWeight(.semibold)
                    .foregroundStyle(Color.primary)
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
            }

            // Prompt + input row
            VStack(alignment: .leading, spacing: Theme.smallPadding) {
                Text(spec.resolvedPrompt)
                    .font(Theme.bodyFont)
                    .foregroundStyle(Color.primary)

                pinField(
                    binding: $pinText,
                    onChange: { model.setPin(from: $0) },
                    accessibilityLabel: spec.resolvedPrompt
                )

                if let repeatPrompt = spec.repeatPrompt {
                    Text(repeatPrompt)
                        .font(Theme.bodyFont)
                        .foregroundStyle(Color.primary)
                    pinField(
                        binding: $repeatText,
                        onChange: { model.setRepeat(from: $0) },
                        accessibilityLabel: repeatPrompt
                    )

                    if !model.pinsMatch && model.repeatLength > 0 {
                        Text(spec.repeatError ?? "Passphrases do not match.")
                            .font(Theme.captionFont)
                            .foregroundStyle(Theme.errorText)
                    }
                }

                Toggle("Show typing", isOn: $model.showTyping)
                    .toggleStyle(.checkbox)
                    .font(Theme.captionFont)
            }

            if let qLabel = spec.qualityBarLabel {
                QualityBar(
                    fraction: model.qualityFraction,
                    label: qLabel,
                    tooltip: spec.qualityBarTooltip
                )
            }

            if spec.allowKeychainSave {
                Toggle("Save in Keychain", isOn: $model.saveToKeychain)
                    .toggleStyle(.checkbox)
                    .font(Theme.bodyFont)
            }

            // Buttons row — pinned to the bottom by VStack growth above.
            HStack(spacing: Theme.smallPadding) {
                Spacer()
                Button(spec.resolvedCancel) {
                    model.cancel()
                }
                .keyboardShortcut(.cancelAction)

                if let notOK = spec.notOKLabel, !notOK.isEmpty {
                    Button(notOK) {
                        // NotOK on a GETPIN is unusual but the protocol
                        // permits it. Treated as a non-confirmation result.
                        // The coordinator translates it to ERR NOT_CONFIRMED.
                        model.cancel()
                    }
                }

                Button(spec.resolvedOK) {
                    model.submit()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(!model.canSubmit)
            }
        }
        .padding(.horizontal, Theme.largePadding)
        .padding(.vertical, Theme.mediumPadding)
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    /// Pick `SecureField` vs `TextField` based on the toggle. We rebuild
    /// the binding in both branches so `.onChange` fires identically.
    @ViewBuilder
    private func pinField(
        binding: Binding<String>,
        onChange: @escaping (String) -> Void,
        accessibilityLabel: String
    ) -> some View {
        Group {
            if model.showTyping {
                TextField("", text: binding)
                    .textFieldStyle(.roundedBorder)
            } else {
                SecureField("", text: binding)
                    .textFieldStyle(.roundedBorder)
            }
        }
        .font(Theme.bodyFont)
        .onChange(of: binding.wrappedValue) { _, newValue in
            onChange(newValue)
        }
        .accessibilityLabel(Text(accessibilityLabel))
    }
}

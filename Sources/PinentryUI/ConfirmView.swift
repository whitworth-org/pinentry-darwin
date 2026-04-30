// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// ConfirmView.swift — the SwiftUI body for the `CONFIRM` Assuan command.
// Two flavours: regular (Cancel / [NotOK] / OK) and `--one-button` which
// renders only an OK acknowledgement.
//
// Visual: matches PinView's header rhythm (icon → title → description)
// for consistency, but uses `exclamationmark.shield.fill` instead of the
// lock icon to signal "decision required" rather than "secret entry".

import SwiftUI

public struct ConfirmView: View {
    public let spec: DialogSpec
    public let onResult: @MainActor (DialogResult) -> Void

    @State private var appeared: Bool = false

    public init(spec: DialogSpec, onResult: @escaping @MainActor (DialogResult) -> Void) {
        self.spec = spec
        self.onResult = onResult
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: Theme.blockPadding) {
            VStack(alignment: .leading, spacing: Theme.mediumPadding) {

                Image(systemName: "exclamationmark.shield.fill")
                    .font(.system(size: Theme.headerIconSize, weight: .semibold))
                    .foregroundStyle(Theme.accent)
                    .accessibilityHidden(true)

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
                        .textSelection(.enabled)
                }
            }

            HStack(spacing: Theme.smallPadding) {
                Spacer()
                if case .confirm(let oneButton) = spec.kind, oneButton {
                    Button(spec.resolvedOK) {
                        onResult(.confirmed)
                    }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(PrimaryButtonStyle())
                } else {
                    Button(spec.resolvedCancel) {
                        onResult(.canceled)
                    }
                    .keyboardShortcut(.cancelAction)

                    if let notOK = spec.notOKLabel, !notOK.isEmpty {
                        Button(notOK) {
                            onResult(.notConfirmed)
                        }
                    }

                    Button(spec.resolvedOK) {
                        onResult(.confirmed)
                    }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(PrimaryButtonStyle())
                }
            }
        }
        .padding(.horizontal, Theme.largePadding)
        .padding(.vertical, Theme.blockPadding)
        .frame(maxWidth: .infinity, alignment: .leading)
        .opacity(appeared ? 1 : 0)
        .offset(y: appeared ? 0 : Theme.entranceTranslate)
        .onAppear {
            withAnimation(.easeOut(duration: Theme.entranceDuration)) {
                appeared = true
            }
        }
    }
}

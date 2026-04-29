// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// ConfirmView.swift — the SwiftUI body for the `CONFIRM` Assuan command.
// Two flavours: regular (Cancel / [NotOK] / OK) and `--one-button` which
// renders only an OK acknowledgement.

import SwiftUI

public struct ConfirmView: View {
    public let spec: DialogSpec
    public let onResult: @MainActor (DialogResult) -> Void

    public init(spec: DialogSpec, onResult: @escaping @MainActor (DialogResult) -> Void) {
        self.spec = spec
        self.onResult = onResult
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
                    .textSelection(.enabled)
            }

            HStack(spacing: Theme.smallPadding) {
                Spacer()
                if case .confirm(let oneButton) = spec.kind, oneButton {
                    Button(spec.resolvedOK) {
                        onResult(.confirmed)
                    }
                    .keyboardShortcut(.defaultAction)
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
                }
            }
        }
        .padding(.horizontal, Theme.largePadding)
        .padding(.vertical, Theme.mediumPadding)
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

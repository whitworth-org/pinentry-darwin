// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// MessageView.swift — the SwiftUI body for the `MESSAGE` Assuan command.
// Title + description + single dismiss button. Always resolves to
// `.confirmed` so the AppDelegate emits `OK` on the wire.

import SwiftUI

public struct MessageView: View {
    public let spec: DialogSpec
    public let onResult: @MainActor (DialogResult) -> Void

    public init(spec: DialogSpec, onResult: @escaping @MainActor (DialogResult) -> Void) {
        self.spec = spec
        self.onResult = onResult
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: Theme.mediumPadding) {

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

            HStack {
                Spacer()
                Button(spec.resolvedOK) {
                    onResult(.confirmed)
                }
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding(.horizontal, Theme.largePadding)
        .padding(.vertical, Theme.mediumPadding)
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

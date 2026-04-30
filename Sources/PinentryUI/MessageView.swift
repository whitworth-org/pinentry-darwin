// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// MessageView.swift — the SwiftUI body for the `MESSAGE` Assuan command.
// Title + description + single dismiss button. Always resolves to
// `.confirmed` so the AppDelegate emits `OK` on the wire.
//
// Visual: matches PinView/ConfirmView header rhythm, uses
// `info.circle.fill` to signal "informational, no decision".

import SwiftUI

public struct MessageView: View {
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

                Image(systemName: "info.circle.fill")
                    .font(.system(size: Theme.headerIconSize, weight: .semibold))
                    .foregroundStyle(Theme.accent)
                    .accessibilityHidden(true)

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

            HStack {
                Spacer()
                Button(spec.resolvedOK) {
                    onResult(.confirmed)
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(PrimaryButtonStyle())
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

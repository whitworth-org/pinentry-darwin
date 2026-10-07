// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// MessageView.swift — the SwiftUI body for the `MESSAGE` Assuan command.
// Title + description + single dismiss button. Always resolves to
// `.confirmed` so the AppDelegate emits `OK` on the wire.
//
// Same layout as PinView (DialogScaffold); `info.circle.fill` signals
// "informational, no decision".

public import SwiftUI

public struct MessageView: View {
    public let spec: DialogSpec
    public let onResult: @MainActor (DialogResult) -> Void

    public init(spec: DialogSpec, onResult: @escaping @MainActor (DialogResult) -> Void) {
        self.spec = spec
        self.onResult = onResult
    }

    public var body: some View {
        DialogScaffold(symbol: "info.circle.fill") {
            DialogTextBlock(spec: spec)
        } footer: {
            DialogButtonRow(spec: spec, oneButton: true) { _ in
                onResult(.confirmed)
            }
        }
    }
}

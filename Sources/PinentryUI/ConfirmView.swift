// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// ConfirmView.swift — the SwiftUI body for the `CONFIRM` Assuan command.
// Two flavours: regular (Cancel / [NotOK] / OK) and `--one-button` which
// renders only an OK acknowledgement.
//
// Same layout as PinView (DialogScaffold); the shield-with-exclamation icon
// signals "decision required" rather than "secret entry".

public import SwiftUI

public struct ConfirmView: View {
    public let spec: DialogSpec
    public let onResult: @MainActor (DialogResult) -> Void

    public init(spec: DialogSpec, onResult: @escaping @MainActor (DialogResult) -> Void) {
        self.spec = spec
        self.onResult = onResult
    }

    private var oneButton: Bool {
        if case .confirm(let oneButton) = spec.kind { return oneButton }
        return false
    }

    public var body: some View {
        DialogScaffold(symbol: "exclamationmark.shield.fill") {
            DialogTextBlock(spec: spec)
            if let error = spec.error.nonEmpty {
                StatusLine(tone: .error, text: error)
            }
        } footer: {
            DialogButtonRow(spec: spec, oneButton: oneButton) { role in
                onResult(role.confirmResult)
            }
        }
    }
}

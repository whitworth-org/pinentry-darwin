// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// SettingsBanner.swift — inline notice row and status badge shared by the
// Settings tabs. Both pair an SF Symbol with text so meaning never depends
// on colour alone.

import AppKit
import SwiftUI

/// A dismissible error or warning row for use as the first row of a Form.
struct SettingsBanner: View {

    enum Kind {
        case error
        case warning

        var symbol: String {
            switch self {
            case .error: "xmark.octagon.fill"
            case .warning: "exclamationmark.triangle.fill"
            }
        }

        var tint: Color {
            switch self {
            case .error: Theme.errorText
            case .warning: Color(NSColor.systemOrange)
            }
        }

        var spokenPrefix: String {
            switch self {
            case .error: "Error"
            case .warning: "Warning"
            }
        }
    }

    let kind: Kind
    let message: String
    let onDismiss: () -> Void

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: Theme.smallPadding) {
            HStack(alignment: .firstTextBaseline, spacing: Theme.smallPadding) {
                Image(systemName: kind.symbol)
                    .foregroundStyle(kind.tint)
                    .accessibilityHidden(true)
                Text(message)
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .accessibilityElement(children: .combine)
            .accessibilityLabel("\(kind.spokenPrefix): \(message)")

            Button("Dismiss", action: onDismiss)
                .controlSize(.small)
        }
        .onAppear {
            AccessibilityNotification.Announcement("\(kind.spokenPrefix): \(message)").post()
        }
    }
}

/// A small capsule with a symbol and a short word, e.g. "Touch ID".
struct SettingsBadge: View {

    let title: String
    let systemImage: String
    let tint: Color

    var body: some View {
        Label {
            Text(title)
        } icon: {
            Image(systemName: systemImage)
                .foregroundStyle(tint)
        }
        .font(.caption2.weight(.medium))
        .foregroundStyle(.secondary)
        .padding(.horizontal, 6)
        .padding(.vertical, 2)
        .background(tint.opacity(0.14), in: Capsule())
        .fixedSize()
    }
}

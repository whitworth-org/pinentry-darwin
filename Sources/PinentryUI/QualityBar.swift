// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// QualityBar.swift — small SwiftUI gauge view bound to the
// PinViewModel.qualityFraction in -1…+1. Colour bands:
//   - negative → systemRed
//   - 0…0.5     → systemYellow
//   - 0.5…1.0   → systemGreen
// All colours come from system NSColor; no hex.

import SwiftUI

public struct QualityBar: View {
    public var fraction: Double
    public var label: String?
    public var tooltip: String?

    public init(fraction: Double, label: String? = nil, tooltip: String? = nil) {
        self.fraction = fraction
        self.label = label
        self.tooltip = tooltip
    }

    private var tint: Color {
        if fraction < 0 { return Theme.errorText }
        if fraction < 0.5 { return Theme.warning }
        return Theme.success
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: Theme.smallPadding / 2) {
            if let label, !label.isEmpty {
                Text(label)
                    .font(Theme.captionFont)
                    .foregroundStyle(Color.secondary)
            }
            Gauge(value: fraction, in: -1...1) {
                Text(label ?? "")
            }
            .gaugeStyle(.linearCapacity)
            .tint(tint)
            .help(tooltip ?? "")
            .accessibilityLabel(Text(label ?? "Passphrase quality"))
            .accessibilityValue(Text(String(format: "%.0f%%", fraction * 100)))
        }
    }
}

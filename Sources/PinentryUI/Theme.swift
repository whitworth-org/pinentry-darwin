// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// Theme.swift — shared spacing, typography, and colour helpers for the
// PinentryUI module. ALL colours come from system NSColor / Color.primary
// / Color.secondary to honour macOS appearance changes live. NO hex
// literals anywhere in this file (or anywhere in this module).

import AppKit
import SwiftUI

public enum Theme {

    // MARK: - Padding (Ghostty conventions: 8 / 12 / 32)

    public static let smallPadding: CGFloat = 8
    public static let mediumPadding: CGFloat = 12
    public static let largePadding: CGFloat = 32

    // MARK: - Typography (system SF fonts)

    public static let titleFont: Font = .system(.title3)
    public static let bodyFont: Font = .system(.body)
    public static let monospacedFont: Font = .system(.body, design: .monospaced)
    public static let captionFont: Font = .system(.caption)

    // MARK: - Colours (system, never hex)

    /// Window-style background — pairs with the NSVisualEffectView underneath.
    public static var windowBackground: Color {
        Color(NSColor.windowBackgroundColor)
    }

    /// Accent colour for the quality bar gauge. Tracks System Settings →
    /// Appearance → Accent colour.
    public static var accent: Color {
        Color(NSColor.controlAccentColor)
    }

    /// Error-text colour. Maps to the system semantic red.
    public static var errorText: Color {
        Color(NSColor.systemRed)
    }

    /// Warning colour for low-but-positive quality scores.
    public static var warning: Color {
        Color(NSColor.systemYellow)
    }

    /// Success colour for high-quality passphrases.
    public static var success: Color {
        Color(NSColor.systemGreen)
    }
}

// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// Theme.swift — shared spacing, typography, motion, and colour tokens for
// the PinentryUI module. ALL colours come from system NSColor / Color.primary
// / Color.secondary so macOS appearance changes propagate live. NO hex
// literals anywhere in this file (or anywhere in this module).
//
// Design direction: refined minimalism with security-craft sensibility.
// One iconographic anchor (lock-shield SF Symbol), strict typographic
// hierarchy with SF Pro Rounded title weight, and a single saturated
// control (the OK button via .borderedProminent). Everything else is
// grayscale carried by NSVisualEffectView material.

import AppKit
import SwiftUI

public enum Theme {

    // MARK: - Padding scale
    //
    // Bumped from {8/12/32} to {8/14/24/40} for 4K/5K presence — the old
    // scale read cramped on Retina+ displays. The horizontal edge padding
    // is the dominant whitespace contributor and gets the largest bump.

    /// Tight intra-block spacing (e.g. between a label and its field).
    public static let smallPadding: CGFloat = 8
    /// Inter-element spacing within a card (e.g. between field and toggle).
    public static let mediumPadding: CGFloat = 14
    /// Block-to-block spacing (e.g. between description and input cluster).
    public static let blockPadding: CGFloat = 24
    /// Edge / outermost padding from the window-content rectangle.
    public static let largePadding: CGFloat = 40

    // MARK: - Typography
    //
    // System SF only — no third-party fonts ship with this binary by
    // policy. Character comes from intentional weight + design pairing,
    // not from substituting a custom typeface. SF Pro Rounded for title
    // gives the dialog a confident, distinctly-Apple feel without
    // departing from the platform vocabulary.

    /// Display heading (SETTITLE / per-dialog header). Uses SF Pro
    /// Rounded at a generous size — readable at arm's length on 5K
    /// while staying tight on a 13" laptop.
    public static let titleFont: Font = .system(size: 22, weight: .semibold, design: .rounded)

    /// Body text (SETDESC / form labels / button text).
    public static let bodyFont: Font = .system(.body)

    /// Slightly larger body for the input fields themselves so the
    /// dot-mask reads at every comfortable viewing distance.
    public static let inputFont: Font = .system(size: 14, weight: .regular)

    /// Monospaced — fingerprints, key-info hashes, anything that needs
    /// to be copy-comparable.
    public static let monospacedFont: Font = .system(.body, design: .monospaced)

    /// Caption — quality readouts, mismatch hints, secondary metadata.
    public static let captionFont: Font = .system(.caption)

    // MARK: - Iconography
    //
    // The dialog gains identity from a single SF Symbol header. Sizing
    // anchors to a fixed point value so it doesn't drift relative to
    // typography on appearance/scale changes.

    /// Header SF Symbol point size. Renders ~32pt visually, scales for
    /// Retina automatically.
    public static let headerIconSize: CGFloat = 32

    /// Inline accessory icons (eye toggle, info adornments).
    public static let inlineIconSize: CGFloat = 14

    // MARK: - Motion
    //
    // One restrained entrance animation, period. No decorative motion
    // anywhere — this is a security modal, not a marketing splash.

    /// Entry-animation duration. 220ms is just-perceptible without
    /// feeling sluggish; matches Apple's own modal sheet timing on
    /// macOS Sequoia.
    public static let entranceDuration: Double = 0.22

    /// Vertical translation (in points) the dialog content slides up
    /// from on first appear. Subtle enough to read as polish, not a
    /// visible stage transition.
    public static let entranceTranslate: CGFloat = 8

    // MARK: - Colours (system, never hex)

    /// Window-style background — pairs with the NSVisualEffectView underneath.
    public static var windowBackground: Color {
        Color(NSColor.windowBackgroundColor)
    }

    /// Accent colour — used sparingly for the borderedProminent OK button
    /// and the quality-bar success band. Tracks System Settings →
    /// Appearance → Accent colour live.
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

    /// A faint hairline tint used for separators between content blocks.
    /// `Color.secondary.opacity(0.18)` lands neutral in both Light and
    /// Dark mode without picking up an accent cast.
    public static var hairline: Color {
        Color.secondary.opacity(0.18)
    }
}

// MARK: - Primary button style
//
// `.borderedProminent` renders a slightly desaturated accent in Dark
// mode for visual hierarchy reasons. We want the dialog's primary
// action to match the SF Symbol header icon's pure accent — when the
// passphrase field has content and OK becomes enabled, the colour
// should read as "this is THE action to take".
//
// PrimaryButtonStyle solid-fills with `Theme.accent` (the same colour
// as `controlAccentColor` driving the icon), uses `.white` text for
// guaranteed contrast on any accent hue the user may have picked, and
// dims subtly while held. Shape and padding mirror the standard macOS
// button so it sits next to the system-styled Cancel button without
// looking out of place.

public struct PrimaryButtonStyle: ButtonStyle {
    public init() {}

    public func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 13, weight: .medium))
            .foregroundStyle(.white)
            .padding(.horizontal, 14)
            .padding(.vertical, 6)
            .background(
                RoundedRectangle(cornerRadius: 6, style: .continuous)
                    .fill(Theme.accent.opacity(configuration.isPressed ? 0.78 : 1.0))
            )
            .contentShape(Rectangle())
    }
}

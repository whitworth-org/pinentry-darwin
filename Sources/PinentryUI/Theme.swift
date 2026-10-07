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

public import AppKit
public import SwiftUI

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
    /// Rounded at the system `.title` size (22pt on macOS), so it scales
    /// with the Text Size accessibility setting like the body text does.
    public static let titleFont: Font = .system(.title, design: .rounded, weight: .semibold)

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

    /// Header SF Symbol point size for views (Confirm/Message) where the
    /// icon sits inline above the title. Renders ~32pt visually.
    public static let headerIconSize: CGFloat = 32

    /// Hero SF Symbol point size for the GETPIN dialog's left-column
    /// anchor. Sized to balance against a multi-line description block
    /// (matches the visual weight of pinentry-mac's padlock illustration).
    public static let heroIconSize: CGFloat = 56

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

    // MARK: - Colours (system, never hex)

    /// Window-style background. Opaque, so Reduce Transparency has nothing
    /// to change; the window paints exactly this colour.
    public static var windowBackground: Color {
        Color(NSColor.windowBackgroundColor)
    }

    /// Accent colour — used sparingly for header icons and as the fill of
    /// `PrimaryButtonStyle`. Tracks System Settings → Appearance → Accent
    /// colour live. Decorative use only: it is not guaranteed to reach text
    /// contrast against the window, so never set text in it.
    public static var accent: Color {
        Color(NSColor.controlAccentColor)
    }

    /// Error-text colour. The system red in Dark mode; darkened in Light
    /// mode, where the plain system red is only about 3:1 against the
    /// window. Reaches 4.5:1 in Light and Dark, normal and Increase Contrast.
    public static var errorText: Color {
        Color(nsColor: NSColor(name: nil) { appearance in errorTextColor(for: appearance) })
    }

    static func errorTextColor(for appearance: NSAppearance) -> NSColor {
        var color = NSColor.systemRed
        appearance.performAsCurrentDrawingAppearance {
            if appearance.bestMatch(from: [.aqua, .darkAqua]) == .aqua {
                color = NSColor.systemRed.blended(withFraction: 0.3, of: .black) ?? .systemRed
            }
        }
        return color
    }

    /// Warning colour for low-but-positive quality scores. A graphic
    /// colour (bars, glyphs), not for text.
    public static var warning: Color {
        Color(NSColor.systemYellow)
    }

    /// Success colour for high-quality passphrases. A graphic colour
    /// (bars, glyphs), not for text.
    public static var success: Color {
        Color(NSColor.systemGreen)
    }

    /// A faint hairline tint used for separators between content blocks.
    /// `Color.secondary.opacity(0.18)` lands neutral in both Light and
    /// Dark mode without picking up an accent cast.
    public static var hairline: Color {
        Color.secondary.opacity(0.18)
    }

    // MARK: - Contrast
    //
    // WCAG 2.x relative luminance and contrast ratio on sRGB colours. Used
    // to pick a label colour for the accent-filled button, because the
    // user-selectable accent ranges from yellow to graphite and no single
    // label colour reads on all of them.

    /// The `NSAppearance` SwiftUI's colour scheme and contrast map to.
    static func appearance(scheme: ColorScheme, contrast: ColorSchemeContrast) -> NSAppearance {
        let name: NSAppearance.Name
        switch (scheme, contrast) {
        case (.dark, .increased): name = .accessibilityHighContrastDarkAqua
        case (.dark, _): name = .darkAqua
        case (_, .increased): name = .accessibilityHighContrastAqua
        default: name = .aqua
        }
        return NSAppearance(named: name) ?? .currentDrawing()
    }

    /// `color` as it renders under the given scheme and contrast, in sRGB.
    static func resolve(
        _ color: NSColor,
        scheme: ColorScheme,
        contrast: ColorSchemeContrast
    ) -> NSColor {
        var resolved = color
        appearance(scheme: scheme, contrast: contrast).performAsCurrentDrawingAppearance {
            resolved = color.usingColorSpace(.sRGB) ?? color
        }
        return resolved
    }

    /// WCAG relative luminance of a colour (alpha ignored). Colours outside
    /// sRGB, such as `NSColor.white`, are converted first.
    static func relativeLuminance(_ input: NSColor) -> Double {
        let color = input.usingColorSpace(.sRGB) ?? input
        func linear(_ channel: CGFloat) -> Double {
            let value = Double(channel)
            return value <= 0.04045 ? value / 12.92 : pow((value + 0.055) / 1.055, 2.4)
        }
        return 0.2126 * linear(color.redComponent)
            + 0.7152 * linear(color.greenComponent)
            + 0.0722 * linear(color.blueComponent)
    }

    /// WCAG contrast ratio between two sRGB colours, 1...21.
    static func contrastRatio(_ first: NSColor, _ second: NSColor) -> Double {
        let lighter = max(relativeLuminance(first), relativeLuminance(second))
        let darker = min(relativeLuminance(first), relativeLuminance(second))
        return (lighter + 0.05) / (darker + 0.05)
    }

    /// Label colour for text on `fill`. White is the platform convention and
    /// is kept while it reaches 3:1 (the WCAG UI-component threshold), which
    /// holds for the blue, purple, pink and red accents. With Increase Contrast
    /// the bar is 4.5:1 (AA text). Below the bar the label is black, which
    /// always passes because the two ratios multiply to 21.
    static func prominentLabel(on fill: NSColor, increasedContrast: Bool) -> NSColor {
        let required = increasedContrast ? 4.5 : 3.0
        return contrastRatio(.white, fill) >= required ? .white : .black
    }
}

// MARK: - Appearance override

extension UISettings.Theme {

    /// The window/app appearance for this choice. `nil` for System: nothing
    /// is overridden, so the window tracks System Settings live.
    public var appearance: NSAppearance? {
        switch self {
        case .system: nil
        case .light: NSAppearance(named: .aqua)
        case .dark: NSAppearance(named: .darkAqua)
        }
    }
}

// MARK: - Primary button style
//
// Solid-fills with the system accent colour, so the dialog's primary action
// matches the SF Symbol header icon and tracks System Settings live. The
// label colour is chosen per fill (see `Theme.prominentLabel`), because
// white text fails contrast on yellow, orange, green and light graphite.
//
// `.glassProminent` was evaluated and not adopted: glass is a navigation-
// layer material, adds no information to a modal passphrase prompt, and
// cannot be verified headlessly. Disabled buttons drop the accent for a
// neutral fill. Increase Contrast adds an outline and pressed state
// darkens instead of fading, so label contrast never drops.

public struct PrimaryButtonStyle: ButtonStyle {
    private let accent: NSColor

    public init() {
        self.accent = .controlAccentColor
    }

    /// Test seam: lets tests render every accent the user can pick.
    init(accent: NSColor) {
        self.accent = accent
    }

    public func makeBody(configuration: Configuration) -> some View {
        PrimaryButtonBody(configuration: configuration, accent: accent)
    }
}

private struct PrimaryButtonBody: View {
    let configuration: ButtonStyleConfiguration
    let accent: NSColor
    @Environment(\.colorScheme) private var scheme
    @Environment(\.colorSchemeContrast) private var contrast
    @Environment(\.isEnabled) private var isEnabled

    private static let shape = RoundedRectangle(cornerRadius: 8, style: .continuous)
    private let disabledFill = Color.secondary.opacity(0.2)

    var body: some View {
        let fill = Theme.resolve(accent, scheme: scheme, contrast: contrast)
        let label = Color(
            nsColor: Theme.prominentLabel(on: fill, increasedContrast: contrast == .increased))
        configuration.label
            .font(Theme.bodyFont.weight(.medium))
            .foregroundStyle(isEnabled ? label : Color.secondary)
            .padding(.horizontal, 14)
            .padding(.vertical, 4)
            .background(Self.shape.fill(isEnabled ? Color(nsColor: fill) : disabledFill))
            .overlay(Self.shape.fill(Color.black.opacity(configuration.isPressed ? 0.18 : 0)))
            .overlay {
                if contrast == .increased {
                    Self.shape.strokeBorder(Color.primary, lineWidth: 1)
                }
            }
            .contentShape(Self.shape)
    }
}

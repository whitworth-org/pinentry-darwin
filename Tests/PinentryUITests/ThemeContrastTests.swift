// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// ThemeContrastTests — colours must stay legible for every accent the user can pick,
// in Light and Dark, with and without Increase Contrast.

import AppKit
import SwiftUI
import XCTest
@testable import PinentryUI

@MainActor
final class ThemeContrastTests: XCTestCase {

    private static let accents: [(String, NSColor)] = [
        ("blue", .systemBlue), ("purple", .systemPurple), ("pink", .systemPink),
        ("red", .systemRed), ("orange", .systemOrange), ("yellow", .systemYellow),
        ("green", .systemGreen), ("graphite", .systemGray), ("current", .controlAccentColor),
    ]

    private static let schemes: [ColorScheme] = [.light, .dark]
    private static let contrasts: [ColorSchemeContrast] = [.standard, .increased]

    func testLuminanceAndRatioMatchWCAGReferenceValues() {
        XCTAssertEqual(Theme.relativeLuminance(.white), 1, accuracy: 0.001)
        XCTAssertEqual(Theme.relativeLuminance(.black), 0, accuracy: 0.001)
        XCTAssertEqual(Theme.contrastRatio(.white, .black), 21, accuracy: 0.01)
        XCTAssertEqual(Theme.contrastRatio(.black, .white), 21, accuracy: 0.01)
        XCTAssertEqual(Theme.contrastRatio(.white, .white), 1, accuracy: 0.001)
    }

    func testProminentLabelReachesThresholdOnEveryAccent() {
        for (name, accent) in Self.accents {
            for scheme in Self.schemes {
                for contrast in Self.contrasts {
                    let fill = Theme.resolve(accent, scheme: scheme, contrast: contrast)
                    let increased = contrast == .increased
                    let label = Theme.prominentLabel(on: fill, increasedContrast: increased)
                    let ratio = Theme.contrastRatio(label, fill)
                    XCTAssertGreaterThanOrEqual(
                        ratio, increased ? 4.5 : 3.0,
                        "label on \(name) accent, \(scheme), \(contrast): \(ratio)")
                }
            }
        }
    }

    // The regression this style change fixes: white text on a light accent.
    func testLightAccentsGetADarkLabelAndSaturatedOnesStayWhite() {
        let yellow = Theme.resolve(.systemYellow, scheme: .light, contrast: .standard)
        XCTAssertEqual(Theme.prominentLabel(on: yellow, increasedContrast: false), .black)

        let navy = NSColor(srgbRed: 0, green: 0, blue: 0.4, alpha: 1)
        XCTAssertEqual(Theme.prominentLabel(on: navy, increasedContrast: false), .white)
        XCTAssertEqual(Theme.prominentLabel(on: navy, increasedContrast: true), .white)
    }

    func testIncreaseContrastTightensTheLabelChoice() {
        // Passes 3:1 with white but not 4.5:1, so only Increase Contrast flips it.
        let midBlue = NSColor(srgbRed: 0, green: 0.45, blue: 1, alpha: 1)
        let ratio = Theme.contrastRatio(.white, midBlue)
        XCTAssertTrue((3.0..<4.5).contains(ratio), "fixture is out of range: \(ratio)")
        XCTAssertEqual(Theme.prominentLabel(on: midBlue, increasedContrast: false), .white)
        XCTAssertEqual(Theme.prominentLabel(on: midBlue, increasedContrast: true), .black)
    }

    func testErrorTextIsLegibleAgainstTheWindow() {
        let error = NSColor(Theme.errorText)
        for scheme in Self.schemes {
            for contrast in Self.contrasts {
                let background = Theme.resolve(
                    .windowBackgroundColor, scheme: scheme, contrast: contrast)
                let text = Theme.resolve(error, scheme: scheme, contrast: contrast)
                let ratio = Theme.contrastRatio(text, background)
                XCTAssertGreaterThanOrEqual(
                    ratio, 4.5, "error text, \(scheme), \(contrast): \(ratio)")
            }
        }
    }
}

// MARK: - Button style

@MainActor
extension ThemeContrastTests {

    /// Darkest and lightest luminance found among the pixels of a rendered button.
    private func extremes(
        accent: NSColor, scheme: ColorScheme
    ) throws -> (min: Double, max: Double) {
        let button = Button("OK") {}
            .buttonStyle(PrimaryButtonStyle(accent: accent))
            .padding(20)
        let rep = try XCTUnwrap(
            RenderSupport.render(
                button, size: CGSize(width: 120, height: 60), scheme: scheme,
                name: "button-\(accent.hashValue)-\(scheme)"))
        var low = 1.0
        var high = 0.0
        for y in 0..<rep.pixelsHigh {
            for x in 0..<rep.pixelsWide {
                guard let color = rep.colorAt(x: x, y: y) else { continue }
                let luminance = Theme.relativeLuminance(color)
                low = min(low, luminance)
                high = max(high, luminance)
            }
        }
        return (low, high)
    }

    // A dark label must actually be drawn on a light accent (text is the darkest
    // pixel), and a light label on a dark accent (text is the lightest pixel).
    func testRenderedButtonLabelContrastsWithItsFill() throws {
        let onYellow = try extremes(accent: .systemYellow, scheme: .light)
        XCTAssertLessThan(onYellow.min, 0.02, "expected a black label on a yellow fill")

        let navy = NSColor(srgbRed: 0, green: 0, blue: 0.4, alpha: 1)
        let onNavy = try extremes(accent: navy, scheme: .light)
        XCTAssertGreaterThan(onNavy.max, 0.95, "expected a white label on a navy fill")
    }
}

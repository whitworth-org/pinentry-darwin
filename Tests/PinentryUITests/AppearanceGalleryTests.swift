// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// AppearanceGalleryTests — renders the dialogs and Settings tabs in Light and Dark
// so appearance work can be inspected. Writes PNGs only when PINENTRY_RENDER_DIR is
// set; otherwise it just proves every view renders in both appearances.

import AppKit
import KeychainStore
import SwiftUI
import XCTest
@testable import PinentryUI

@MainActor
final class AppearanceGalleryTests: XCTestCase {

    private static let schemes: [(String, ColorScheme)] = [("light", .light), ("dark", .dark)]

    private func spec(_ kind: DialogSpec.Kind) -> DialogSpec {
        DialogSpec(
            kind: kind,
            title: "Passphrase",
            description: "Please enter the passphrase to unlock the OpenPGP secret key:\n"
                + "\"Ryan Whitworth <ryan@whitworth.org>\"\n"
                + "256-bit ED25519 key, ID 0123456789ABCDEF",
            prompt: "Passphrase:",
            error: nil,
            keyInfo: .key(
                mode: "s", fingerprint: "0123 4567 89AB CDEF 0123 4567 89AB CDEF 0123 4567")
        )
    }

    func testRenderDialogsAtCandidateWidths() throws {
        for (name, scheme) in Self.schemes {
            for width in [480.0, 560.0, 726.0] {
                let model = PinViewModel(
                    spec: spec(.pin), showTypingByDefault: false, saveByDefault: false,
                    onResult: { _ in })
                let pin = PinView(spec: spec(.pin), model: model).frame(width: width)
                let image = RenderSupport.render(
                    pin, size: CGSize(width: width, height: 330), scheme: scheme,
                    name: "pin-\(name)-\(Int(width))")
                XCTAssertNotNil(image)
            }
            let confirm = ConfirmView(spec: spec(.confirm(oneButton: false))) { _ in }
                .frame(width: 560)
            RenderSupport.render(
                confirm, size: CGSize(width: 560, height: 260), scheme: scheme,
                name: "confirm-\(name)")
        }
    }

    func testRenderPrimaryButtonOnEveryAccent() {
        let accents: [(String, NSColor)] = [
            ("blue", .systemBlue), ("purple", .systemPurple), ("pink", .systemPink),
            ("red", .systemRed), ("orange", .systemOrange), ("yellow", .systemYellow),
            ("green", .systemGreen), ("graphite", .systemGray), ("current", .controlAccentColor),
        ]
        for (name, scheme) in Self.schemes {
            let grid = VStack(alignment: .leading, spacing: 10) {
                ForEach(accents, id: \.0) { label, accent in
                    HStack(spacing: 12) {
                        Text(label).frame(width: 70, alignment: .trailing)
                        Button("Cancel") {}.buttonStyle(.bordered)
                        Button("OK") {}.buttonStyle(PrimaryButtonStyle(accent: accent))
                        Button("OK") {}.buttonStyle(PrimaryButtonStyle(accent: accent))
                            .disabled(true)
                    }
                }
            }.padding(20)
            let image = RenderSupport.render(
                grid, size: CGSize(width: 340, height: 400), scheme: scheme,
                name: "buttons-\(name)")
            XCTAssertNotNil(image)
        }
    }

    func testRenderSettingsTabs() {
        for (name, scheme) in Self.schemes {
            let appearance = AppearanceSettingsView(
                settings: .constant(UISettings()), keychainPrefs: .constant(UserPrefs()),
                onChange: { _ in })
            let behaviour = BehaviourSettingsView(
                settings: .constant(UISettings(defaultTimeout: 30)), onChange: { _ in })
            RenderSupport.render(
                appearance, size: CGSize(width: 520, height: 220), scheme: scheme,
                name: "settings-appearance-\(name)")
            RenderSupport.render(
                behaviour, size: CGSize(width: 520, height: 420), scheme: scheme,
                name: "settings-behaviour-\(name)")
        }
    }

    func testRenderConfirmWithLargerText() {
        let confirm = ConfirmView(spec: spec(.confirm(oneButton: false))) { _ in }
            .frame(width: 480)
            .dynamicTypeSize(.xxxLarge)
        let image = RenderSupport.render(
            confirm, size: CGSize(width: 480, height: 420), scheme: .light,
            name: "confirm-light-480-largertext")
        XCTAssertNotNil(image)
    }
}

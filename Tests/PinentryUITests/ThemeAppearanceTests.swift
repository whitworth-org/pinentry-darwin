// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// ThemeAppearanceTests — the Light/Dark/System choice must reach SwiftUI content and
// AppKit controls through the window's `appearance`, and System must override nothing.

import AppKit
import SecureMemory
import SwiftUI
import XCTest
@testable import PinentryUI

@MainActor
final class ThemeAppearanceTests: XCTestCase {

    private func name(of appearance: NSAppearance?) -> NSAppearance.Name? {
        appearance?.name
    }

    private func isDark(_ appearance: NSAppearance) -> Bool {
        appearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua
    }

    private func spin(_ seconds: TimeInterval = 0.2) {
        RunLoop.current.run(until: Date().addingTimeInterval(seconds))
    }

    private func window(for theme: UISettings.Theme, box: RenderSupport.Box) -> NSWindow {
        let probe = RenderSupport.Probe(box: box, content: Color.clear.frame(width: 40, height: 40))
        let window = makePinentryWindow(rootView: probe, title: nil, theme: theme)
        window.contentViewController?.view.layoutSubtreeIfNeeded()
        window.contentViewController?.view.displayIfNeeded()
        return window
    }

    func testThemeMapsToAppearance() {
        XCTAssertNil(UISettings.Theme.system.appearance, "System must override nothing")
        XCTAssertEqual(name(of: UISettings.Theme.light.appearance), .aqua)
        XCTAssertEqual(name(of: UISettings.Theme.dark.appearance), .darkAqua)
    }

    func testWindowAppearanceIsSetPerTheme() {
        for theme in UISettings.Theme.allCases {
            let window = makePinentryWindow(rootView: Color.clear, title: nil, theme: theme)
            XCTAssertEqual(
                name(of: window.appearance), name(of: theme.appearance),
                "window.appearance for \(theme)")
        }
    }

    func testSwiftUIContentFollowsExplicitTheme() {
        for (theme, expected) in [(UISettings.Theme.light, ColorScheme.light), (.dark, .dark)] {
            let box = RenderSupport.Box()
            let window = window(for: theme, box: box)
            XCTAssertEqual(box.value.scheme, expected, "SwiftUI colour scheme for \(theme)")
            withExtendedLifetime(window) {}
        }
    }

    func testSystemThemeTracksTheSystemAppearance() {
        let box = RenderSupport.Box()
        let window = window(for: .system, box: box)
        defer { withExtendedLifetime(window) {} }

        XCTAssertNil(window.appearance)
        let systemIsDark = isDark(NSApp.effectiveAppearance)
        XCTAssertEqual(box.value.scheme, systemIsDark ? .dark : .light)
        XCTAssertEqual(isDark(window.effectiveAppearance), systemIsDark)
    }

    func testChangingAppearanceUpdatesAnAlreadyOpenWindow() {
        let box = RenderSupport.Box()
        let window = window(for: .light, box: box)
        defer { withExtendedLifetime(window) {} }
        XCTAssertEqual(box.value.scheme, .light)

        window.appearance = UISettings.Theme.dark.appearance
        spin()
        window.contentViewController?.view.displayIfNeeded()

        XCTAssertEqual(box.value.scheme, .dark, "an open window must follow a theme change")
    }

    func testAppKitSecureFieldFollowsExplicitTheme() throws {
        for theme in [UISettings.Theme.light, .dark] {
            let model = PinViewModel(
                spec: DialogSpec(kind: .pin), showTypingByDefault: false,
                saveByDefault: false, onResult: { _ in })
            let window = makePinentryWindow(
                rootView: PinView(spec: DialogSpec(kind: .pin), model: model),
                title: nil, theme: theme)
            let root = try XCTUnwrap(window.contentViewController?.view)
            root.layoutSubtreeIfNeeded()
            spin()

            let field = try XCTUnwrap(
                Self.firstSubview(of: NSSecureTextField.self, in: root),
                "PinView must host an NSSecureTextField")
            XCTAssertEqual(
                isDark(field.effectiveAppearance), theme == .dark,
                "AppKit control must follow the explicit \(theme) choice")
        }
    }

    private static func firstSubview<T: NSView>(of type: T.Type, in view: NSView) -> T? {
        if let match = view as? T { return match }
        for child in view.subviews {
            if let match = firstSubview(of: type, in: child) { return match }
        }
        return nil
    }
}

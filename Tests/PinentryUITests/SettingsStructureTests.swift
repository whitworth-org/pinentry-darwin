// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// SettingsStructureTests — tab order and symbols, the preference toolbar's
// selection wiring, and the plain-language copy helpers.

import AppKit
import KeychainStore
import SwiftUI
import XCTest
@testable import PinentryUI

@MainActor
final class SettingsStructureTests: XCTestCase {

    // MARK: - Tabs

    func testTabOrderAndTitles() {
        XCTAssertEqual(
            SettingsTab.allCases.map(\.title),
            ["Appearance", "Behaviour", "Keychain", "Per-key policy", "SSH", "About"]
        )
    }

    func testEveryTabHasADistinctSystemSymbol() {
        let symbols = SettingsTab.allCases.map(\.symbol)
        XCTAssertEqual(Set(symbols).count, symbols.count)
        for symbol in symbols {
            let image = NSImage(systemSymbolName: symbol, accessibilityDescription: nil)
            XCTAssertNotNil(image, symbol)
        }
    }

    // MARK: - Toolbar

    private final class SelectionBox {
        var value = SettingsTab.appearance
    }

    func testToolbarListsEveryTabAndReportsSelection() throws {
        let box = SelectionBox()
        let controller = SettingsToolbarController(
            selection: Binding(get: { box.value }, set: { box.value = $0 })
        )
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 560, height: 440),
            styleMask: [.titled],
            backing: .buffered,
            defer: false
        )
        window.isReleasedWhenClosed = false

        controller.install(on: window)
        let toolbar = try XCTUnwrap(controller.toolbar)

        XCTAssertEqual(window.toolbarStyle, .preference)
        XCTAssertEqual(
            controller.toolbarDefaultItemIdentifiers(toolbar).map(\.rawValue),
            SettingsTab.allCases.map(\.rawValue)
        )
        XCTAssertEqual(toolbar.selectedItemIdentifier?.rawValue, "appearance")
        XCTAssertEqual(window.title, "Appearance")

        let ssh = try XCTUnwrap(
            controller.toolbar(
                toolbar,
                itemForItemIdentifier: .init("ssh"),
                willBeInsertedIntoToolbar: false
            )
        )
        XCTAssertEqual(ssh.label, "SSH")
        XCTAssertNotNil(ssh.image)

        controller.itemClicked(ssh)
        XCTAssertEqual(box.value, .ssh)
        controller.syncSelection()
        XCTAssertEqual(toolbar.selectedItemIdentifier?.rawValue, "ssh")
        XCTAssertEqual(window.title, "SSH")
    }

    func testToolbarIgnoresUnknownIdentifiers() throws {
        let controller = SettingsToolbarController(selection: .constant(.appearance))
        let toolbar = NSToolbar(identifier: "test")
        XCTAssertNil(
            controller.toolbar(
                toolbar,
                itemForItemIdentifier: .init("nope"),
                willBeInsertedIntoToolbar: false
            )
        )
    }

    // MARK: - Copy helpers

    func testCacheTitles() {
        XCTAssertEqual(KeyPolicyText.cacheTitle(0), "Until cleared")
        XCTAssertEqual(KeyPolicyText.cacheTitle(3600), "1 hour")
        XCTAssertEqual(KeyPolicyText.cacheTitle(60), "1 minute")
        XCTAssertEqual(KeyPolicyText.cacheTitle(90 * 60), "90 minutes")
        XCTAssertEqual(KeyPolicyText.cacheTitle(45), "45 seconds")
    }

    func testCacheOptionsKeepAStoredCustomDuration() {
        XCTAssertEqual(KeyPolicyText.cacheOptions(including: 0), [0, 300, 3600, 28800, 86400])
        XCTAssertEqual(
            KeyPolicyText.cacheOptions(including: 7200),
            [0, 300, 3600, 7200, 28800, 86400],
            "a stored value outside the menu must stay selectable"
        )
    }

    func testPolicySummary() {
        let policy = KeyPolicy(
            biometry: .biometryAny,
            accessibility: .whenUnlocked,
            cacheTTLSeconds: 300
        )
        XCTAssertEqual(
            KeyPolicyText.summary(policy),
            "Touch ID, any enrolled fingerprint · 5 minutes"
        )
    }

    func testKeyIdentifierFormatting() {
        let fingerprint = "9f3a1c7e5b2d40869ac1e3b7d5f20184c6a9e37b"
        XCTAssertEqual(
            KeyIdentifier.grouped(fingerprint),
            "9F3A 1C7E 5B2D 4086 9AC1 E3B7 D5F2 0184 C6A9 E37B"
        )
        XCTAssertEqual(KeyIdentifier.abbreviated(fingerprint), "9F3A1C7E…C6A9E37B")
        XCTAssertEqual(KeyIdentifier.abbreviated("abcd"), "ABCD", "short ids are not elided")
        XCTAssertEqual(KeyIdentifier.grouped(""), "")
    }
}

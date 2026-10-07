// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// UISettingsTests — persistence round-trips for the Settings that remain after the
// unwired fields were removed, and compatibility with blobs written before that.

import Foundation
import XCTest
@testable import PinentryUI

final class UISettingsTests: XCTestCase {

    /// A store over a throwaway suite. The suite name lets tests reach the same
    /// domain through a second `UserDefaults` (the actor owns the first).
    private func makeStore() throws -> (UISettingsStore, UserDefaults, String) {
        let suite = "org.whitworth.pinentry-darwin.tests.\(UUID().uuidString)"
        let store = UISettingsStore(defaults: UserDefaults(suiteName: suite))
        return (store, try XCTUnwrap(UserDefaults(suiteName: suite)), suite)
    }

    func testRoundTripPreservesEveryField() async throws {
        let (store, defaults, suite) = try makeStore()
        defer { defaults.removePersistentDomain(forName: suite) }
        let settings = UISettings(
            theme: .dark, defaultTimeout: 45,
            secureKeyboardEntry: false, clearPasteboardOnSubmit: false)

        await store.save(settings)

        let loaded = await store.load()
        XCTAssertEqual(loaded, settings)
    }

    func testMissingBlobLoadsDefaults() async throws {
        let (store, defaults, suite) = try makeStore()
        defer { defaults.removePersistentDomain(forName: suite) }
        let loaded = await store.load()
        XCTAssertEqual(loaded, UISettings())
        XCTAssertEqual(loaded.theme, .system)
        XCTAssertEqual(loaded.defaultTimeout, 0)
    }

    // Blobs saved by earlier versions carry keys for fields that no longer exist.
    func testBlobWithRemovedFieldsStillLoadsTheRemainingValues() async throws {
        let (store, defaults, suite) = try makeStore()
        defer { defaults.removePersistentDomain(forName: suite) }
        let legacy = """
            {"theme":"light","titlebarStyle":"hidden","defaultTimeout":20,
             "closeOnBlur":true,"beepOnWeakPassphrase":true,
             "secureKeyboardEntry":false,"clearPasteboardOnSubmit":true}
            """
        defaults.set(Data(legacy.utf8), forKey: UISettingsStore.key)

        let loaded = await store.load()

        XCTAssertEqual(loaded.theme, .light)
        XCTAssertEqual(loaded.defaultTimeout, 20)
        XCTAssertFalse(loaded.secureKeyboardEntry)
    }

    func testCorruptBlobLoadsDefaults() async throws {
        let (store, defaults, suite) = try makeStore()
        defer { defaults.removePersistentDomain(forName: suite) }
        defaults.set(Data("not json".utf8), forKey: UISettingsStore.key)
        let loaded = await store.load()
        XCTAssertEqual(loaded, UISettings())
    }
}

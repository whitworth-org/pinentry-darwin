// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// UserPrefsTests: precedence rules between our own suite and the read-only
// org.gpgtools.common fallback. All tests use ephemeral UserDefaults suites
// so they never touch the developer's real preferences.

import XCTest
@testable import KeychainStore

final class UserPrefsTests: XCTestCase {

    // MARK: - Test fixtures

    private var ownSuiteName: String = ""
    private var gpgSuiteName: String = ""
    private var ownDefaults: UserDefaults!
    private var gpgDefaults: UserDefaults!

    override func setUp() {
        super.setUp()
        ownSuiteName = "test.own." + UUID().uuidString
        gpgSuiteName = "test.gpgtools." + UUID().uuidString
        ownDefaults = UserDefaults(suiteName: ownSuiteName)!
        gpgDefaults = UserDefaults(suiteName: gpgSuiteName)!
    }

    override func tearDown() {
        // Wipe both suites to keep state out of the test machine.
        ownDefaults.removePersistentDomain(forName: ownSuiteName)
        gpgDefaults.removePersistentDomain(forName: gpgSuiteName)
        ownDefaults = nil
        gpgDefaults = nil
        super.tearDown()
    }

    private func makePrefs(useGPGTools: Bool = true) -> UserPrefs {
        UserPrefs(
            defaults: ownDefaults,
            gpgToolsDefaults: useGPGTools ? gpgDefaults : nil
        )
    }

    // MARK: - keychainEnabled

    func testKeychainEnabledDefaultsTrueWhenNothingSet() {
        let prefs = makePrefs()
        XCTAssertTrue(prefs.keychainEnabled)
    }

    func testKeychainEnabledOwnSuiteWinsOverGPGTools() {
        // GPGTools says disabled, but own suite explicitly enables.
        gpgDefaults.set(true, forKey: "DisableKeychain")
        ownDefaults.set(true, forKey: "KeychainEnabled")

        let prefs = makePrefs()
        XCTAssertTrue(prefs.keychainEnabled)
    }

    func testKeychainEnabledOwnSuiteCanDisable() {
        ownDefaults.set(false, forKey: "KeychainEnabled")
        let prefs = makePrefs()
        XCTAssertFalse(prefs.keychainEnabled)
    }

    func testKeychainEnabledGPGToolsDisableKeychain() {
        gpgDefaults.set(true, forKey: "DisableKeychain")
        let prefs = makePrefs()
        XCTAssertFalse(prefs.keychainEnabled)
    }

    func testKeychainEnabledGPGToolsUseKeychainFalse() {
        gpgDefaults.set(false, forKey: "UseKeychain")
        let prefs = makePrefs()
        XCTAssertFalse(prefs.keychainEnabled)
    }

    func testKeychainEnabledGPGToolsUseKeychainTrueIsRedundant() {
        // UseKeychain=true is the default — we still return true.
        gpgDefaults.set(true, forKey: "UseKeychain")
        let prefs = makePrefs()
        XCTAssertTrue(prefs.keychainEnabled)
    }

    func testKeychainEnabledIgnoresGPGToolsWhenSuiteDisabled() {
        gpgDefaults.set(true, forKey: "DisableKeychain")
        let prefs = makePrefs(useGPGTools: false)
        XCTAssertTrue(prefs.keychainEnabled)
    }

    // MARK: - saveByDefault

    func testSaveByDefaultDefaultsTrue() {
        let prefs = makePrefs()
        XCTAssertTrue(prefs.saveByDefault)
    }

    func testSaveByDefaultExplicitFalse() {
        ownDefaults.set(false, forKey: "SaveByDefault")
        let prefs = makePrefs()
        XCTAssertFalse(prefs.saveByDefault)
    }

    func testSaveByDefaultExplicitTrue() {
        ownDefaults.set(true, forKey: "SaveByDefault")
        let prefs = makePrefs()
        XCTAssertTrue(prefs.saveByDefault)
    }

    // MARK: - showTypingByDefault

    func testShowTypingDefaultsFalse() {
        let prefs = makePrefs()
        XCTAssertFalse(prefs.showTypingByDefault)
    }

    func testShowTypingOwnSuiteWins() {
        gpgDefaults.set(true, forKey: "ShowPassphrase")
        ownDefaults.set(false, forKey: "ShowTyping")
        let prefs = makePrefs()
        XCTAssertFalse(prefs.showTypingByDefault)
    }

    func testShowTypingFallsBackToGPGTools() {
        gpgDefaults.set(true, forKey: "ShowPassphrase")
        let prefs = makePrefs()
        XCTAssertTrue(prefs.showTypingByDefault)
    }

    func testShowTypingFallbackHonoursFalse() {
        gpgDefaults.set(false, forKey: "ShowPassphrase")
        let prefs = makePrefs()
        XCTAssertFalse(prefs.showTypingByDefault)
    }

    // MARK: - Setters

    func testSettersWriteToOwnSuite() {
        var prefs = makePrefs()
        prefs.set(keychainEnabled: false)
        prefs.set(saveByDefault: false)
        prefs.set(showTypingByDefault: true)

        // Re-instantiate with the same backing stores; values must persist.
        let prefs2 = makePrefs()
        XCTAssertFalse(prefs2.keychainEnabled)
        XCTAssertFalse(prefs2.saveByDefault)
        XCTAssertTrue(prefs2.showTypingByDefault)

        // And nothing was written to the gpgtools fallback suite.
        XCTAssertNil(gpgDefaults.object(forKey: "DisableKeychain"))
        XCTAssertNil(gpgDefaults.object(forKey: "UseKeychain"))
        XCTAssertNil(gpgDefaults.object(forKey: "ShowPassphrase"))
    }
}

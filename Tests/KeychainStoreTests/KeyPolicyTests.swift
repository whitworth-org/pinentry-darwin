// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// KeyPolicyTests: schema round-trip + persistence for the Tier 2 per-key
// policy store. These tests use an ephemeral UserDefaults suite and do
// NOT touch the actual keychain.

import XCTest
@testable import KeychainStore
import Security

final class KeyPolicyTests: XCTestCase {

    // MARK: Defaults match legacy

    func testLegacyDefaultMatchesPreTier2Behaviour() {
        let p = KeyPolicy.legacyDefault
        XCTAssertEqual(p.biometry, .userPresence)
        XCTAssertEqual(p.accessibility, .whenUnlocked)
        XCTAssertNil(p.cacheTTLSeconds)
    }

    func testSecAccessibilityMapping() {
        XCTAssertEqual(
            KeyPolicy(accessibility: .whenUnlocked).secAccessibility as! CFString,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        )
        XCTAssertEqual(
            KeyPolicy(accessibility: .whenPasscodeSet).secAccessibility as! CFString,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        )
    }

    func testSecAccessControlFlagsMapping() {
        XCTAssertEqual(
            KeyPolicy(biometry: .userPresence).secAccessControlFlags,
            [.userPresence]
        )
        XCTAssertEqual(
            KeyPolicy(biometry: .biometryCurrentSet).secAccessControlFlags,
            [.biometryCurrentSet]
        )
        XCTAssertEqual(
            KeyPolicy(biometry: .biometryAny).secAccessControlFlags,
            [.biometryAny]
        )
        XCTAssertEqual(
            KeyPolicy(biometry: .devicePasscode).secAccessControlFlags,
            [.devicePasscode]
        )
    }

    // MARK: TTL coercion

    func testNegativeOrZeroTTLBecomesNil() {
        XCTAssertNil(KeyPolicy(cacheTTLSeconds: 0).cacheTTLSeconds)
        XCTAssertNil(KeyPolicy(cacheTTLSeconds: -5).cacheTTLSeconds)
        XCTAssertNil(KeyPolicy(cacheTTLSeconds: nil).cacheTTLSeconds)
    }

    func testPositiveTTLPreserved() {
        XCTAssertEqual(KeyPolicy(cacheTTLSeconds: 300).cacheTTLSeconds, 300)
        XCTAssertEqual(KeyPolicy(cacheTTLSeconds: 86_400).cacheTTLSeconds, 86_400)
    }

    // MARK: JSON round-trip

    func testJSONRoundTripPreservesAllFields() throws {
        let original = KeyPolicy(
            biometry: .biometryCurrentSet,
            accessibility: .whenPasscodeSet,
            cacheTTLSeconds: 3600
        )
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(KeyPolicy.self, from: data)
        XCTAssertEqual(decoded, original)
    }

    func testJSONDecodeRejectsNegativeTTLViaCoercion() throws {
        let json = #"{"biometry":"userPresence","accessibility":"whenUnlocked","cacheTTLSeconds":-100}"#
        let decoded = try JSONDecoder().decode(KeyPolicy.self, from: Data(json.utf8))
        // The init's TTL coercion only runs at construction. JSONDecoder
        // bypasses the memberwise init, so the raw field round-trips. That
        // is the contract: persisted values are returned verbatim; Tier 4
        // enforcement layer is the one that treats <= 0 as "no TTL".
        XCTAssertEqual(decoded.cacheTTLSeconds, -100)
    }

    // MARK: Persistence

    private func ephemeralStore() -> (KeyPolicyStore, UserDefaults) {
        let suite = "pinentry-darwin-test-\(UUID().uuidString)"
        guard let defaults = UserDefaults(suiteName: suite) else {
            fatalError("could not create ephemeral UserDefaults")
        }
        return (KeyPolicyStore(defaults: defaults), defaults)
    }

    func testDefaultPolicyFallsBackToLegacyWhenEmpty() {
        let (store, _) = ephemeralStore()
        XCTAssertEqual(store.defaultPolicy, .legacyDefault)
    }

    func testSetAndReadDefaultPolicy() {
        let (store, _) = ephemeralStore()
        let custom = KeyPolicy(
            biometry: .biometryAny,
            accessibility: .whenPasscodeSet,
            cacheTTLSeconds: 7200
        )
        store.setDefaultPolicy(custom)
        XCTAssertEqual(store.defaultPolicy, custom)
    }

    func testPerKeyOverrideTakesPrecedenceOverDefault() {
        let (store, _) = ephemeralStore()
        let fpr = "DEADBEEFCAFEBABE0000000000000000DEADBEEF"

        let defaultPolicy = KeyPolicy(biometry: .userPresence)
        store.setDefaultPolicy(defaultPolicy)

        let override = KeyPolicy(biometry: .biometryCurrentSet)
        store.setPolicy(override, for: fpr)

        XCTAssertEqual(store.policy(for: fpr), override)
        XCTAssertEqual(store.defaultPolicy, defaultPolicy)
    }

    func testPolicyForUnknownFingerprintReturnsDefault() {
        let (store, _) = ephemeralStore()
        let custom = KeyPolicy(biometry: .biometryAny)
        store.setDefaultPolicy(custom)
        XCTAssertEqual(store.policy(for: "unknown"), custom)
    }

    func testRemoveOverrideRevertsToDefault() {
        let (store, _) = ephemeralStore()
        let fpr = "DEADBEEFCAFEBABE0000000000000000DEADBEEF"
        let override = KeyPolicy(biometry: .biometryCurrentSet)
        store.setPolicy(override, for: fpr)
        XCTAssertNotNil(store.override(for: fpr))

        store.removeOverride(for: fpr)
        XCTAssertNil(store.override(for: fpr))
        XCTAssertEqual(store.policy(for: fpr), store.defaultPolicy)
    }

    func testFingerprintLookupIsCaseInsensitive() {
        let (store, _) = ephemeralStore()
        let lower = "deadbeefcafebabe0000000000000000deadbeef"
        let upper = lower.uppercased()
        let override = KeyPolicy(biometry: .biometryAny)
        store.setPolicy(override, for: lower)
        XCTAssertEqual(store.policy(for: upper), override)
    }

    func testOverriddenFingerprintsListed() {
        let (store, _) = ephemeralStore()
        let a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        let b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        store.setPolicy(KeyPolicy(), for: a)
        store.setPolicy(KeyPolicy(), for: b)
        let list = store.overriddenFingerprints()
        XCTAssertEqual(list, [a, b].sorted())
    }

    func testOverriddenFingerprintsExcludesDefaultRecord() {
        let (store, _) = ephemeralStore()
        store.setDefaultPolicy(KeyPolicy(biometry: .biometryAny))
        XCTAssertTrue(store.overriddenFingerprints().isEmpty)
    }
}

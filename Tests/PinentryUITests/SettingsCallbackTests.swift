// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// SettingsCallbackTests — the Forget / Forget-all callbacks wrap Keychain
// deletes that can block on a biometric prompt, so the Settings views must
// invoke them off the main thread even though the awaiting task is main-actor.
// They also throw, and the views must keep a key's policy when they do.

import Foundation
import KeychainStore
import SwiftUI
import Synchronization
import XCTest
@testable import PinentryUI

private struct DeleteFailed: Error {}

/// An in-memory stand-in for the Keychain's list of saved fingerprints.
private final class FakeKeychain: Sendable {
    private let items: Mutex<[String]>

    init(_ items: [String]) { self.items = Mutex(items) }

    var fingerprints: [String] { items.withLock { $0 } }

    func delete(_ fingerprint: String) {
        items.withLock { $0.removeAll { $0 == fingerprint } }
    }
}

final class SettingsCallbackTests: XCTestCase {

    private let fingerprint = "0123456789ABCDEF0123456789ABCDEF01234567"
    private let strict = KeyPolicy(
        biometry: .biometryCurrentSet,
        accessibility: .whenPasscodeSet,
        cacheTTLSeconds: 3600
    )

    /// An isolated policy store so tests never touch the user's defaults.
    private func makeStore() -> KeyPolicyStore {
        let suite = "SettingsCallbackTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        addTeardownBlock { UserDefaults(suiteName: suite)?.removePersistentDomain(forName: suite) }
        return KeyPolicyStore(defaults: defaults)
    }

    /// A model over an in-memory "keychain" that `forget` deletes from unless it throws.
    @MainActor
    private func makeModel(
        store: KeyPolicyStore,
        keychain: FakeKeychain,
        failing error: (any Error & Sendable)? = nil,
        withForget: Bool = true
    ) -> PerKeyPolicyModel {
        let callback: PerKeyPolicyView.ForgetCallback = { fpr in
            if let error { throw error }
            keychain.delete(fpr)
        }
        return PerKeyPolicyModel(
            store: store,
            enumerate: { keychain.fingerprints },
            forget: withForget ? callback : nil
        )
    }

    // MARK: - Threading

    @MainActor
    func testForgetCallbackRunsOffMainThread() async throws {
        let ranOnMain = Mutex<Bool?>(nil)
        let callback: PerKeyPolicyView.ForgetCallback = { _ in
            ranOnMain.withLock { $0 = Thread.isMainThread }
        }

        XCTAssertTrue(Thread.isMainThread, "precondition: awaiting from the main actor")
        try await callback("ABCDEF")

        XCTAssertEqual(ranOnMain.withLock { $0 }, false)
    }

    @MainActor
    func testClearAllCallbackRunsOffMainThread() async throws {
        let ranOnMain = Mutex<Bool?>(nil)
        let view = KeychainSettingsView(
            keychainPrefs: .constant(UserPrefs()),
            clearAll: { ranOnMain.withLock { $0 = Thread.isMainThread } }
        )

        try await view.clearAll?()

        XCTAssertEqual(ranOnMain.withLock { $0 }, false)
    }

    // MARK: - Per-key Forget

    @MainActor
    func testForgetSuccessRemovesOverrideAndRow() async {
        let store = makeStore()
        store.setPolicy(strict, for: fingerprint)
        let keychain = FakeKeychain([fingerprint])
        let model = makeModel(store: store, keychain: keychain)
        await model.load()
        XCTAssertEqual(model.rows.map(\.fingerprint), [fingerprint])
        XCTAssertTrue(model.rows[0].hasOverride)

        await model.forget(fingerprint)

        XCTAssertNil(store.override(for: fingerprint))
        XCTAssertTrue(model.rows.isEmpty)
        XCTAssertNil(model.errorMessage)
        XCTAssertNil(model.forgetting)
    }

    @MainActor
    func testForgetFailureKeepsOverrideAndSurfacesError() async {
        let store = makeStore()
        store.setPolicy(strict, for: fingerprint)
        let keychain = FakeKeychain([fingerprint])
        let model = makeModel(
            store: store,
            keychain: keychain,
            failing: KeychainStoreError.userCanceled
        )
        await model.load()

        await model.forget(fingerprint)

        XCTAssertEqual(store.override(for: fingerprint), strict, "override must survive")
        XCTAssertEqual(model.rows.map(\.fingerprint), [fingerprint], "row must survive")
        XCTAssertTrue(model.rows[0].hasOverride)
        let message = model.errorMessage ?? ""
        XCTAssertTrue(message.contains("Authentication was cancelled."), message)
        XCTAssertTrue(message.contains("01234567…01234567"), message)
        XCTAssertNil(model.forgetting)
    }

    @MainActor
    func testForgetCancellationKeepsOverride() async {
        let store = makeStore()
        store.setPolicy(strict, for: fingerprint)
        let model = makeModel(
            store: store,
            keychain: FakeKeychain([fingerprint]),
            failing: CancellationError()
        )
        await model.load()

        await model.forget(fingerprint)

        XCTAssertNotNil(store.override(for: fingerprint))
        XCTAssertNotNil(model.errorMessage)
    }

    @MainActor
    func testForgetWithoutCallbackDoesNothing() async {
        let store = makeStore()
        store.setPolicy(strict, for: fingerprint)
        let model = makeModel(
            store: store,
            keychain: FakeKeychain([fingerprint]),
            withForget: false
        )
        await model.load()

        await model.forget(fingerprint)

        XCTAssertFalse(model.canForget)
        XCTAssertNotNil(store.override(for: fingerprint))
        XCTAssertNil(model.errorMessage)
    }

    @MainActor
    func testErrorCanBeDismissedAndRetrySucceeds() async {
        let store = makeStore()
        store.setPolicy(strict, for: fingerprint)
        let keychain = FakeKeychain([fingerprint])
        let shouldFail = Mutex(true)
        let model = PerKeyPolicyModel(
            store: store,
            enumerate: { keychain.fingerprints },
            forget: { fpr in
                if shouldFail.withLock({ $0 }) { throw DeleteFailed() }
                keychain.delete(fpr)
            }
        )
        await model.load()
        await model.forget(fingerprint)
        XCTAssertNotNil(model.errorMessage)

        model.errorMessage = nil
        shouldFail.withLock { $0 = false }
        await model.forget(fingerprint)

        XCTAssertNil(model.errorMessage)
        XCTAssertNil(store.override(for: fingerprint))
        XCTAssertTrue(model.rows.isEmpty)
    }

    @MainActor
    func testSetAndResetOverrideUpdateRows() async {
        let store = makeStore()
        let model = makeModel(store: store, keychain: FakeKeychain([fingerprint]))
        await model.load()
        XCTAssertFalse(model.rows[0].hasOverride)

        model.setPolicy(strict, for: fingerprint)
        XCTAssertTrue(model.rows[0].hasOverride)
        XCTAssertEqual(model.rows[0].policy, strict)

        model.resetOverride(for: fingerprint)
        XCTAssertFalse(model.rows[0].hasOverride)
        XCTAssertEqual(model.rows[0].policy, model.defaultPolicy)
    }

    // MARK: - Forget all

    @MainActor
    func testForgetAllModelRecordsSuccess() async {
        let model = ForgetAllModel()

        await model.run { }

        XCTAssertNil(model.errorMessage)
        XCTAssertNotNil(model.notice)
        XCTAssertFalse(model.isRunning)
    }

    @MainActor
    func testForgetAllModelSurfacesFailureWithoutSuccessNotice() async {
        let model = ForgetAllModel()

        await model.run { throw KeychainStoreError.userCanceled }

        XCTAssertNil(model.notice)
        XCTAssertTrue(model.errorMessage?.contains("Authentication was cancelled.") == true)
        XCTAssertFalse(model.isRunning)
    }

    func testForgetAllKeepsOverridesOfFailedDeletesAndReportsCounts() {
        let cleared = Mutex<[String]>([])
        let overridesRemoved = Mutex<[String]>([])

        XCTAssertThrowsError(
            try SavedPassphrases.forgetAll(
                fingerprints: ["aa", "bb", "cc"],
                clear: { fpr in
                    if fpr == "bb" { throw KeychainStoreError.userCanceled }
                    cleared.withLock { $0.append(fpr) }
                },
                removeOverride: { fpr in overridesRemoved.withLock { $0.append(fpr) } }
            )
        ) { error in
            XCTAssertEqual(
                error as? ForgetAllError,
                ForgetAllError(failed: 1, total: 3, firstReason: "Authentication was cancelled.")
            )
        }

        XCTAssertEqual(cleared.withLock { $0 }, ["aa", "cc"], "every entry is attempted")
        XCTAssertEqual(overridesRemoved.withLock { $0 }, ["aa", "cc"])
    }

    func testForgetAllWithNothingSavedSucceeds() throws {
        try SavedPassphrases.forgetAll(
            fingerprints: [],
            clear: { _ in XCTFail("nothing to clear") },
            removeOverride: { _ in XCTFail("nothing to remove") }
        )
    }

    // MARK: - Error text

    func testFailureReasonNamesKeychainErrors() {
        XCTAssertEqual(
            SavedPassphrases.failureReason(for: KeychainStoreError.userCanceled),
            "Authentication was cancelled."
        )
        XCTAssertFalse(
            SavedPassphrases.failureReason(for: KeychainStoreError.unexpectedStatus(-25308))
                .isEmpty
        )
    }
}

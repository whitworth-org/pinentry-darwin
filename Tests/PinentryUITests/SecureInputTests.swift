// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// SecureInputTests — verify the Carbon SKE wrapper maintains a balanced
// refcount across paired enable/disable calls and that `reset()` zeros
// any outstanding enables.
//
// We do NOT test the kernel-level effect of EnableSecureEventInput
// directly (no public API to introspect that without entitlements).
// Pinning the wrapper's accounting catches the most common bug class —
// an unbalanced enable that leaves the menu-bar lock badge stuck.

import XCTest
@testable import PinentryUI

@MainActor
final class SecureInputTests: XCTestCase {

    override func setUp() async throws {
        SecureInput.reset()
        XCTAssertEqual(SecureInput.refCount, 0,
                       "test setup must start with SKE refCount at 0")
    }

    override func tearDown() async throws {
        SecureInput.reset()
        XCTAssertEqual(SecureInput.refCount, 0,
                       "test teardown must restore SKE refCount to 0")
    }

    func testEnableIncrementsRefCount() {
        XCTAssertTrue(SecureInput.enable())
        XCTAssertEqual(SecureInput.refCount, 1)
        XCTAssertTrue(SecureInput.isActive)
    }

    func testDisableDecrementsRefCount() {
        SecureInput.enable()
        XCTAssertTrue(SecureInput.disable())
        XCTAssertEqual(SecureInput.refCount, 0)
        XCTAssertFalse(SecureInput.isActive)
    }

    func testNestedPairsBalance() {
        // Three enables, three disables — refCount returns to zero.
        SecureInput.enable()
        SecureInput.enable()
        SecureInput.enable()
        XCTAssertEqual(SecureInput.refCount, 3)

        SecureInput.disable()
        SecureInput.disable()
        XCTAssertEqual(SecureInput.refCount, 1)
        XCTAssertTrue(SecureInput.isActive)

        SecureInput.disable()
        XCTAssertEqual(SecureInput.refCount, 0)
        XCTAssertFalse(SecureInput.isActive)
    }

    func testDisableUnderflowClampsToZero() {
        // Caller bug: disable() before enable(). Our local refCount
        // should not go negative; the kernel-level count is at zero
        // after the call, which is also the desired floor.
        _ = SecureInput.disable()
        _ = SecureInput.disable()
        XCTAssertEqual(SecureInput.refCount, 0)
    }

    func testResetZerosOutstandingEnables() {
        SecureInput.enable()
        SecureInput.enable()
        XCTAssertEqual(SecureInput.refCount, 2)

        let emitted = SecureInput.reset()
        XCTAssertEqual(emitted, 2)
        XCTAssertEqual(SecureInput.refCount, 0)
        XCTAssertFalse(SecureInput.isActive)
    }

    func testResetIsNoOpWhenAlreadyZero() {
        let emitted = SecureInput.reset()
        XCTAssertEqual(emitted, 0)
        XCTAssertEqual(SecureInput.refCount, 0)
    }
}

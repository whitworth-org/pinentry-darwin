// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// PasteboardGuardTests — verify the conservative clear-on-paste flow.
//
// All tests inject a uniquely-named NSPasteboard so we never touch the
// user's `NSPasteboard.general` during automated runs. Each test owns
// its own pasteboard and releases it on tear-down via `releaseGlobally`.

import AppKit
import XCTest
@testable import PinentryUI

@MainActor
final class PasteboardGuardTests: XCTestCase {

    private var pasteboard: NSPasteboard!

    override func setUp() async throws {
        // Unique name per test so parallel runs don't share state.
        pasteboard = NSPasteboard(name: NSPasteboard.Name("pinentry-test-\(UUID().uuidString)"))
    }

    override func tearDown() async throws {
        pasteboard.releaseGlobally()
        pasteboard = nil
    }

    // MARK: snapshot

    func testSnapshotReturnsCurrentChangeCount() {
        let observed = PasteboardGuard.snapshot(of: pasteboard)
        XCTAssertEqual(observed, pasteboard.changeCount)
    }

    func testSnapshotIsStableWithoutWrites() {
        let a = PasteboardGuard.snapshot(of: pasteboard)
        let b = PasteboardGuard.snapshot(of: pasteboard)
        XCTAssertEqual(a, b, "back-to-back snapshots without writes must match")
    }

    // MARK: clearIfAdvanced — disabled path

    func testClearIfAdvancedReturnsFalseWhenDisabled() {
        let baseline = PasteboardGuard.snapshot(of: pasteboard)
        pasteboard.clearContents()
        pasteboard.setString("residue", forType: .string)
        XCTAssertGreaterThan(pasteboard.changeCount, baseline)

        let cleared = PasteboardGuard.clearIfAdvanced(
            since: baseline,
            enabled: false,
            on: pasteboard
        )
        XCTAssertFalse(cleared, "disabled flag must short-circuit")
        XCTAssertEqual(pasteboard.string(forType: .string), "residue",
                       "disabled flag must not touch the pasteboard")
    }

    // MARK: clearIfAdvanced — enabled but no advance

    func testClearIfAdvancedReturnsFalseWhenNoAdvance() {
        let baseline = PasteboardGuard.snapshot(of: pasteboard)
        let cleared = PasteboardGuard.clearIfAdvanced(
            since: baseline,
            enabled: true,
            on: pasteboard
        )
        XCTAssertFalse(cleared, "no pasteboard write since baseline => no clear")
    }

    // MARK: clearIfAdvanced — enabled and pasteboard advanced

    func testClearIfAdvancedClearsWhenEnabledAndAdvanced() {
        let baseline = PasteboardGuard.snapshot(of: pasteboard)
        // Simulate a paste happening after the dialog opened.
        pasteboard.clearContents()
        pasteboard.setString("secret-paste", forType: .string)
        XCTAssertGreaterThan(pasteboard.changeCount, baseline)
        XCTAssertEqual(pasteboard.string(forType: .string), "secret-paste")

        let cleared = PasteboardGuard.clearIfAdvanced(
            since: baseline,
            enabled: true,
            on: pasteboard
        )
        XCTAssertTrue(cleared)
        XCTAssertNil(pasteboard.string(forType: .string),
                     "pasteboard must be empty after clear")
    }

    // MARK: idempotency

    func testClearIfAdvancedIsIdempotent() {
        let baseline = PasteboardGuard.snapshot(of: pasteboard)
        pasteboard.clearContents()
        pasteboard.setString("hello", forType: .string)

        let firstCall = PasteboardGuard.clearIfAdvanced(
            since: baseline,
            enabled: true,
            on: pasteboard
        )
        // The clearContents() call itself advances changeCount, so a
        // second call would observe a new advance and clear again. That
        // is safe (the second clear is a no-op on an already-empty
        // pasteboard) — the contract is "if pasteboard moved past the
        // *original* baseline, clear at least once".
        let secondCall = PasteboardGuard.clearIfAdvanced(
            since: baseline,
            enabled: true,
            on: pasteboard
        )
        XCTAssertTrue(firstCall)
        XCTAssertTrue(secondCall,
                      "second call still observes advance vs original baseline")
        XCTAssertNil(pasteboard.string(forType: .string))
    }
}

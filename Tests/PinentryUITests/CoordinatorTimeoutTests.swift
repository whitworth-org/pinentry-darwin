// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// CoordinatorTimeoutTests — SETTIMEOUT must fire while the dialog is up.
// `NSApp.runModal(for:)` spins the run loop in the modal-panel mode only, so
// a timer registered for the default mode alone never fires during a dialog.
// These tests spin that mode directly instead of showing a window.

import AppKit
import XCTest
@testable import PinentryUI

@MainActor
final class CoordinatorTimeoutTests: XCTestCase {

    func testTimeoutFiresWhileModalPanelModeIsSpinning() {
        // AppKit registers the modal-panel mode as a common mode on startup.
        _ = NSApplication.shared
        var fired = false
        let timer = PinentryCoordinator.scheduleTimeout(after: 0.05) { fired = true }
        defer { timer.invalidate() }

        spin(.modalPanel, until: { fired }, timeout: 2)

        XCTAssertTrue(fired, "timeout never fired inside the modal-panel run-loop mode")
    }

    func testInvalidatedTimeoutDoesNotFire() {
        _ = NSApplication.shared
        var fired = false
        let timer = PinentryCoordinator.scheduleTimeout(after: 0.05) { fired = true }
        timer.invalidate()

        spin(.modalPanel, until: { fired }, timeout: 0.3)

        XCTAssertFalse(fired, "an invalidated timeout must not fire")
    }

    func testGpgAgentTimeoutWinsOverTheConfiguredDefault() {
        XCTAssertEqual(PinentryCoordinator.effectiveTimeout(requested: 60, fallback: 30), 60)
    }

    func testDefaultTimeoutAppliesWhenGpgAgentSendsNone() {
        XCTAssertEqual(PinentryCoordinator.effectiveTimeout(requested: nil, fallback: 30), 30)
    }

    // SETTIMEOUT 0 is gpg-agent explicitly asking for no timeout.
    func testExplicitZeroDisablesTheTimeoutDespiteTheDefault() {
        XCTAssertNil(PinentryCoordinator.effectiveTimeout(requested: 0, fallback: 30))
    }

    func testNoTimeoutWhenNeitherSourceSetsOne() {
        XCTAssertNil(PinentryCoordinator.effectiveTimeout(requested: nil, fallback: 0))
        XCTAssertNil(PinentryCoordinator.effectiveTimeout(requested: nil, fallback: -5))
    }

    private func spin(_ mode: RunLoop.Mode, until done: () -> Bool, timeout: TimeInterval) {
        let deadline = Date().addingTimeInterval(timeout)
        while !done(), Date() < deadline {
            _ = RunLoop.current.run(mode: mode, before: deadline)
        }
    }
}

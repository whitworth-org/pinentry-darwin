// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.

import XCTest
import AppKit
@testable import PinentryUI

@MainActor
final class PinentryWindowTests: XCTestCase {

    // Regression: NSWindow defaults `isReleasedWhenClosed` to true. Under
    // Swift ARC this double-frees on dialog dismissal and surfaces as a
    // use-after-free during the first layout/constraint pass on GETPIN.
    // pinentry-darwin must keep it false so Swift owns the lifetime.
    func testIsReleasedWhenClosedFalse() {
        let win = PinentryWindow(contentRect: NSRect(x: 0, y: 0, width: 480, height: 200))
        XCTAssertFalse(
            win.isReleasedWhenClosed,
            "PinentryWindow must opt out of releaseWhenClosed; otherwise ARC + AppKit double-free"
        )
    }

    func testCanBecomeKeyAndMain() {
        let win = PinentryWindow(contentRect: NSRect(x: 0, y: 0, width: 480, height: 200))
        XCTAssertTrue(win.canBecomeKey, "SecureField focus requires canBecomeKey")
        XCTAssertTrue(win.canBecomeMain)
    }

    func testTitlebarFlags() {
        let win = PinentryWindow(contentRect: NSRect(x: 0, y: 0, width: 480, height: 200))
        XCTAssertTrue(win.titlebarAppearsTransparent)
        XCTAssertEqual(win.titleVisibility, .hidden)
        XCTAssertTrue(win.styleMask.contains(.fullSizeContentView))
    }

    // Snapshot suppression: WindowServer must not capture pinentry
    // contents into Mission Control / Cmd-Tab thumbnails. With Show
    // typing enabled, an unguarded snapshot would land plaintext in
    // the per-user window cache.
    func testSnapshotSuppressionConfigured() {
        let win = PinentryWindow(contentRect: NSRect(x: 0, y: 0, width: 480, height: 200))
        XCTAssertEqual(win.sharingType, .none,
                       "sharingType must be .none so WindowServer skips snapshot capture")
        XCTAssertTrue(win.collectionBehavior.contains(.transient),
                      "collectionBehavior must include .transient")
        XCTAssertTrue(win.collectionBehavior.contains(.ignoresCycle),
                      "collectionBehavior must include .ignoresCycle")
    }

    // NSPanel migration: PinentryWindow is now an NSPanel subclass for
    // its modal-friendly behaviours. The previous NSWindow base would
    // not surface `worksWhenModal` or `becomesKeyOnlyIfNeeded` in a
    // semantically meaningful way.
    func testIsNSPanelSubclass() {
        let win = PinentryWindow(contentRect: NSRect(x: 0, y: 0, width: 480, height: 200))
        XCTAssertTrue(win is NSPanel,
                      "PinentryWindow must be an NSPanel for modal-tolerant behaviour")
    }

    // becomesKeyOnlyIfNeeded = false ensures the panel takes key status
    // the moment it appears so the secure field receives the first
    // keystroke without an intervening mouse click. The NSPanel default
    // depends on style mask and can be true under some configurations;
    // we pin it false explicitly.
    func testBecomesKeyOnlyIfNeededIsFalse() {
        let win = PinentryWindow(contentRect: NSRect(x: 0, y: 0, width: 480, height: 200))
        XCTAssertFalse(win.becomesKeyOnlyIfNeeded,
                       "panel must grab key status immediately for first-keystroke entry")
    }

    func testWorksWhenModalIsTrue() {
        let win = PinentryWindow(contentRect: NSRect(x: 0, y: 0, width: 480, height: 200))
        XCTAssertTrue(win.worksWhenModal,
                      "panel must keep accepting events during sibling modal sessions")
    }

    func testFloatingLevel() {
        let win = PinentryWindow(contentRect: NSRect(x: 0, y: 0, width: 480, height: 200))
        XCTAssertEqual(win.level, .floating,
                       "pinentry must float above full-screen apps and terminals")
    }

    func testCloseButtonInterceptedWhenHandlerSet() {
        let win = PinentryWindow(contentRect: NSRect(x: 0, y: 0, width: 480, height: 200))
        var fired = 0
        win.onCloseRequested = { fired += 1 }
        win.performClose(nil)
        XCTAssertEqual(fired, 1, "performClose must route through onCloseRequested when set")
    }

    // Regression: macOS's standard close button can call `close()` directly
    // (bypassing performClose:) — pinentry-darwin must catch that path too,
    // otherwise the red-X dismisses the window without emitting
    // BUTTON_INFO close + ERR and the binary blocks forever.
    func testDirectCloseInterceptedWhenHandlerSet() {
        let win = PinentryWindow(contentRect: NSRect(x: 0, y: 0, width: 480, height: 200))
        var fired = 0
        win.onCloseRequested = { fired += 1 }
        win.close()
        XCTAssertEqual(fired, 1, "close() must route through onCloseRequested when set")
    }

    // The resolver dismisses the window after delivering its result via
    // `pw.isResolvingDismissal = true; pw.close()`. That path must NOT
    // re-fire onCloseRequested, otherwise we deliver twice.
    func testResolverDrivenCloseDoesNotRefire() {
        let win = PinentryWindow(contentRect: NSRect(x: 0, y: 0, width: 480, height: 200))
        var fired = 0
        win.onCloseRequested = { fired += 1 }
        win.isResolvingDismissal = true
        win.close()
        XCTAssertEqual(fired, 0, "resolver-driven close must bypass onCloseRequested")
    }
}

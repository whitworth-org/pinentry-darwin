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

    func testCloseButtonInterceptedWhenHandlerSet() {
        let win = PinentryWindow(contentRect: NSRect(x: 0, y: 0, width: 480, height: 200))
        var fired = 0
        win.onCloseRequested = { fired += 1 }
        win.performClose(nil)
        XCTAssertEqual(fired, 1, "performClose must route through onCloseRequested when set")
    }
}

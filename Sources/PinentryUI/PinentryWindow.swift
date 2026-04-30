// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// Window styling adapted from Ghostty (MIT). Source:
//   /Users/rwhitworth/Development/ghostty/macos/Sources/Features/Terminal/Window Styles/
// Specifically `TransparentTitlebarTerminalWindow.swift` and
// `HiddenTitlebarTerminalWindow.swift` — we mirror the appearance flags
// (transparent titlebar, hidden title, full-size content view, visual
// effect background) without copying any tab/fullscreen logic since our
// windows are short-lived modal pinentry dialogs.

import AppKit

/// A small custom NSWindow that hosts pinentry dialogs.
///
/// Visual goals:
/// - Transparent titlebar that matches the underlying NSVisualEffectView.
/// - No window title text (the SwiftUI body renders its own).
/// - Floats above other apps while modal, but does not steal the dock.
/// - Tracks the system Light/Dark appearance live (no `appearance` override).
@MainActor
public final class PinentryWindow: NSWindow {

    /// Lower bound. Below this the dialog feels cramped on any display.
    public static let minWidth: CGFloat = 480

    /// Upper bound. Above this the dialog feels stretched even on 5K+;
    /// past this the line measure for the description becomes too wide
    /// for comfortable reading.
    public static let maxWidth: CGFloat = 760

    /// Fraction of the screen's visible width to occupy. 0.34 lands at
    /// ~514pt on a 1512pt-wide 14" laptop and clamps to 760pt on 4K/5K
    /// — generous on Retina+ without becoming dominant.
    private static let screenFraction: CGFloat = 0.34

    /// Width of the next pinentry dialog, computed against the supplied
    /// screen (or `NSScreen.main`). Always lands in `[minWidth, maxWidth]`,
    /// rounded to the nearest even integer so the result lands on a
    /// whole-pixel boundary at @2x and avoids half-pixel layout artefacts.
    public static func preferredWidth(for screen: NSScreen? = NSScreen.main) -> CGFloat {
        let visible = (screen ?? NSScreen.screens.first)?.visibleFrame.width ?? 1440
        let raw = visible * screenFraction
        let clamped = min(max(raw, minWidth), maxWidth)
        return roundToEven(clamped)
    }

    /// Round to the nearest even integer (Banker's rounding for ties).
    private static func roundToEven(_ value: CGFloat) -> CGFloat {
        let rounded = value.rounded()
        let asInt = Int(rounded)
        return CGFloat(asInt.isMultiple(of: 2) ? asInt : asInt + 1)
    }

    /// Closure invoked when the user clicks the red close button. Set by
    /// `HostingController.makePinentryWindow` so the coordinator can resume
    /// its continuation with `.windowClosed`.
    public var onCloseRequested: (@MainActor () -> Void)?

    public init(contentRect: NSRect) {
        super.init(
            contentRect: contentRect,
            styleMask: [.titled, .closable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )

        // CRITICAL: NSWindow's designated initializer defaults
        // `isReleasedWhenClosed` to true, which double-frees a Swift-owned
        // NSWindow under ARC (AppKit autoreleases on close *and* ARC
        // releases on the last Swift reference dropping). The result is a
        // use-after-free during the first layout/constraint pass — the
        // very symptom we hit on GETPIN. Mirror pinentry-mac's
        // `releasedWhenClosed="NO"` and let Swift own the lifetime.
        isReleasedWhenClosed = false

        // Titlebar: transparent + invisible title so the visual-effect
        // background bleeds all the way to the top edge.
        titlebarAppearsTransparent = true
        titleVisibility = .hidden

        // Hide the miniaturise/zoom traffic lights — pinentry dialogs are
        // modal and these actions don't apply. Keep the close button
        // visible so the user has an explicit escape that maps to
        // `BUTTON_INFO close`.
        standardWindowButton(.miniaturizeButton)?.isHidden = true
        standardWindowButton(.zoomButton)?.isHidden = true

        // Allow drag-anywhere so users can reposition without a visible bar.
        isMovableByWindowBackground = true

        // Floating level keeps the dialog visible over Terminal/iTerm even
        // if focus shifts; we deliberately stay above .normal but below
        // panels like .modalPanel to avoid stealing from system sheets.
        level = .floating

        // Tabs make no sense for a modal pinentry.
        tabbingMode = .disallowed

        // Do NOT set `appearance` — leaving it nil makes the window
        // inherit `NSApp.effectiveAppearance` so System / Light / Dark
        // changes propagate live. The Settings appearance override is
        // applied at the SwiftUI hosting view level instead.

        // Background tint that adapts to system appearance. We do NOT
        // assign an NSVisualEffectView as contentView here: the caller
        // sets contentViewController = NSHostingController(...), which
        // replaces contentView and breaks the visual-effect's
        // autoresizing model, causing an Auto Layout update-cycle
        // exception under SwiftUI's constraint-based layout. Solid
        // windowBackgroundColor reads correctly in both Light and Dark
        // modes; layered translucency can return in v1.1 via
        // NSViewRepresentable wrapped inside the SwiftUI tree.
        backgroundColor = .windowBackgroundColor
    }

    // The window must be able to become key so SecureField receives
    // keyboard focus immediately on present.
    public override var canBecomeKey: Bool { true }
    public override var canBecomeMain: Bool { true }

    // Intercept the close button (red traffic light). Returning false
    // suppresses the default close so the coordinator can decide what to
    // emit on the wire (`BUTTON_INFO close` then ERR).
    public override func performClose(_ sender: Any?) {
        if let onCloseRequested {
            onCloseRequested()
            return
        }
        super.performClose(sender)
    }
}

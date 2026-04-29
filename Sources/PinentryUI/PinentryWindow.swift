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

    /// Width of every pinentry dialog. Height is driven by the SwiftUI body.
    public static let preferredWidth: CGFloat = 480

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

        // Background: an NSVisualEffectView with the under-window
        // material. This is the same material Ghostty uses for terminal
        // windows and adapts automatically to Light / Dark.
        let effect = NSVisualEffectView()
        effect.material = .underWindowBackground
        effect.blendingMode = .behindWindow
        effect.state = .active
        effect.autoresizingMask = [.width, .height]
        contentView = effect
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

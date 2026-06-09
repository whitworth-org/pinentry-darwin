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

/// A small custom NSPanel that hosts pinentry dialogs.
///
/// Why NSPanel rather than NSWindow: NSPanel is the conventional AppKit
/// class for short-lived modal prompts. It inherits everything NSWindow
/// does and adds a few opt-in behaviours we want — `worksWhenModal`
/// (the panel keeps accepting events even if another application is
/// running a modal session at the same time) and an explicit non-
/// default for `becomesKeyOnlyIfNeeded` (false here: we WANT the panel
/// to become key the moment it's shown, since the whole purpose is
/// keystroke entry).
///
/// Visual goals:
/// - Transparent titlebar that matches the underlying NSVisualEffectView.
/// - No window title text (the SwiftUI body renders its own).
/// - Floats above other apps while modal, but does not steal the dock.
/// - Tracks the system Light/Dark appearance live (no `appearance` override).
@MainActor
public final class PinentryWindow: NSPanel {

    /// Lower bound. Below this the description column gets too narrow
    /// for the smartcard-info multi-line content.
    public static let minWidth: CGFloat = 680

    /// Upper bound. Above this the line measure for the description
    /// becomes too wide for comfortable reading even on 4K/5K hosts.
    public static let maxWidth: CGFloat = 840

    /// Fraction of the screen's visible width to occupy. 0.48 lands at
    /// ~726pt on a 1512pt-wide 14" laptop and clamps to 840pt on
    /// 4K/5K — landscape proportions, halfway between pinentry-mac's
    /// original ~480pt and the doubled ~960pt.
    private static let screenFraction: CGFloat = 0.48

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

        // CRITICAL: NSWindow's (and NSPanel's) designated initializer
        // defaults `isReleasedWhenClosed` to true, which double-frees a
        // Swift-owned window under ARC (AppKit autoreleases on close
        // *and* ARC releases on the last Swift reference dropping). The
        // result is a use-after-free during the first layout/constraint
        // pass — the very symptom we hit on GETPIN. Mirror pinentry-mac's
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

        // Opt the window out of WindowServer snapshot capture. Without
        // this, Mission Control / Cmd-Tab / Dock minimise / Stage
        // Manager preview thumbnails capture the live dialog contents —
        // a plaintext leak when the user has Show typing enabled.
        // `.transient` additionally keeps the window out of Spaces /
        // Mission Control entirely; `.ignoresCycle` skips it from
        // Cmd-` window cycling.
        //
        // Note: macOS has no public `setContentProtected` API analogous
        // to iOS's UIWindow.isContentProtected. `sharingType = .none`
        // is the comprehensive public hardening on macOS — it blocks
        // ScreenCaptureKit consumers (incl. third-party recorders and
        // `screencapture`), Mission Control snapshots, Cmd-Tab and
        // Dock previews, Stage Manager thumbnails, and the share-sheet
        // window picker. There is no additional notarization-safe API
        // to layer on top.
        sharingType = .none
        collectionBehavior = [.transient, .ignoresCycle]

        // I-6: opt out of window state restoration. A restorable window
        // lets AppKit persist an encoded snapshot of the window (and its
        // restoration class) to the per-user saved-application-state
        // store on disk, and can capture a window-image snapshot during
        // the save. For a passphrase prompt that means dialog state /
        // contents could be serialised under ~/Library/Saved Application
        // State. pinentry dialogs are single-shot and never want to be
        // restored on relaunch, so we disable restoration outright. This
        // is the notarization-safe NSWindow/NSPanel opt-out; it composes
        // with `sharingType = .none` above (which blocks live snapshot
        // capture by the WindowServer).
        isRestorable = false

        // NSPanel-specific behaviours (no-ops on plain NSWindow):
        //   becomesKeyOnlyIfNeeded = false → the panel takes key status
        //     the moment it appears, so the secure field receives the
        //     first keystroke without an intervening click.
        //   worksWhenModal = true → the panel keeps accepting events
        //     even if a sibling NSApp modal session is active, e.g. an
        //     authorization sheet posted by another component.
        becomesKeyOnlyIfNeeded = false
        worksWhenModal = true

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

    /// Set true by the coordinator's resolver before it calls `close()` to
    /// dismiss the window after a result has been delivered. While this is
    /// true, our `close()` override forwards directly to super instead of
    /// re-entering `onCloseRequested` (which would resolve a second time).
    public var isResolvingDismissal: Bool = false

    // Intercept the close button (red traffic light). Returning false
    // suppresses the default close so the coordinator can decide what to
    // emit on the wire (`BUTTON_INFO close` then ERR).
    public override func performClose(_ sender: Any?) {
        if !isResolvingDismissal, let onCloseRequested {
            onCloseRequested()
            return
        }
        super.performClose(sender)
    }

    // Belt-and-suspenders: macOS may invoke `close()` directly from the
    // standard window-close path (private button action, command-w, etc.)
    // without first routing through `performClose:`. Catch that path too,
    // and gate on `isResolvingDismissal` so the resolver's own `close()`
    // call doesn't re-enter the callback.
    public override func close() {
        if !isResolvingDismissal, let onCloseRequested {
            onCloseRequested()
            return
        }
        super.close()
    }
}

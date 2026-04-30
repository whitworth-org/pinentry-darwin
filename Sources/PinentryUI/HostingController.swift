// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// HostingController.swift — small helper that wraps a SwiftUI view in an
// `NSHostingController` and stuffs it inside a `PinentryWindow`. The
// resulting window is sized to fit its SwiftUI content (height) at the
// fixed preferred width.

import AppKit
import SwiftUI

/// Build a `PinentryWindow` that hosts the supplied SwiftUI view.
///
/// - Parameters:
///   - rootView: the SwiftUI view to embed. Theme-override modifiers
///     should already be applied by the caller (so `.preferredColorScheme`
///     is *only* set for explicit Light/Dark, never for System).
///   - title: optional accessibility title (`title` is hidden visually but
///     is still announced to VoiceOver and shown in window-menu lists).
///
/// - Returns: a configured but **not yet visible** `PinentryWindow`.
///   The caller is responsible for `makeKeyAndOrderFront` + `center`.
@MainActor
public func makePinentryWindow<V: View>(rootView: V, title: String?) -> NSWindow {
    // Compute the dialog width once against the active screen so the
    // dialog scales with display density. 4K/5K hosts get more breathing
    // room; laptop screens stay compact.
    let preferredWidth = PinentryWindow.preferredWidth()

    // Initial frame — width is final, height is placeholder. The
    // SwiftUI tree's `.frame(width:)` modifier pins the width, and
    // assigning the hosting controller as `contentViewController`
    // makes the window track its `preferredContentSize` automatically
    // (default behaviour on macOS 14+). No explicit sizingOptions and
    // no manual `setContentSize` — both of those caused Auto Layout
    // update-cycle exceptions in earlier iterations.
    let initialRect = NSRect(
        x: 0, y: 0,
        width: preferredWidth, height: 200
    )
    let window = PinentryWindow(contentRect: initialRect)
    if let title { window.title = title }

    let constrained = rootView.frame(width: preferredWidth)
    let hosting = NSHostingController(rootView: constrained)
    window.contentViewController = hosting

    return window
}

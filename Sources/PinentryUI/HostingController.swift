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
    // Initial frame — height is a placeholder; SwiftUI will request its
    // intrinsic size and we resize the window once below.
    let initialRect = NSRect(
        x: 0, y: 0,
        width: PinentryWindow.preferredWidth, height: 200
    )
    let window = PinentryWindow(contentRect: initialRect)
    if let title { window.title = title }

    let hosting = NSHostingController(rootView: rootView)
    window.contentViewController = hosting

    // Constrain width; let height float to the SwiftUI body's intrinsic.
    if let view = hosting.view as NSView? {
        view.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            view.widthAnchor.constraint(equalToConstant: PinentryWindow.preferredWidth)
        ])
    }

    // Resize to fit the hosting controller's preferred content size.
    let fitted = hosting.view.fittingSize
    let frame = NSRect(
        x: 0, y: 0,
        width: PinentryWindow.preferredWidth,
        height: max(fitted.height, 120)
    )
    window.setContentSize(frame.size)

    return window
}

// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// DialogRenderHarness.swift — hosts a dialog view in a window that is never
// ordered front, so layout can be measured, the AppKit tree inspected and,
// when PINENTRY_RENDER_DIR is set, a PNG written for visual review.

import AppKit
import SwiftUI

@MainActor
final class MountedDialog {
    static let dialogWidth: CGFloat = 700

    let window: NSWindow
    let hosting: NSView
    let size: CGSize

    init<V: View>(
        _ view: V,
        appearance: NSAppearance.Name = .aqua,
        width: CGFloat = MountedDialog.dialogWidth
    ) {
        let scheme: ColorScheme = appearance == .darkAqua ? .dark : .light
        let root = view
            .frame(width: width)
            .background(Color(nsColor: .windowBackgroundColor))
            .preferredColorScheme(scheme)
        let hosting = NSHostingView(rootView: root)
        hosting.appearance = NSAppearance(named: appearance)
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: width, height: 300),
            styleMask: [.titled],
            backing: .buffered,
            defer: false
        )
        window.isReleasedWhenClosed = false
        window.appearance = NSAppearance(named: appearance)
        window.contentView = hosting
        size = hosting.fittingSize
        window.setContentSize(size)
        hosting.frame = NSRect(origin: .zero, size: size)
        for _ in 0..<5 {
            RunLoop.current.run(until: Date().addingTimeInterval(0.05))
            hosting.layoutSubtreeIfNeeded()
        }
        self.window = window
        self.hosting = hosting
    }

    /// First descendant of the given AppKit type.
    func find<T: NSView>(_ type: T.Type) -> T? {
        func walk(_ view: NSView) -> T? {
            if let match = view as? T { return match }
            for child in view.subviews {
                if let match = walk(child) { return match }
            }
            return nil
        }
        return walk(hosting)
    }

    func pngData() -> Data {
        guard let rep = hosting.bitmapImageRepForCachingDisplay(in: hosting.bounds) else {
            return Data()
        }
        hosting.cacheDisplay(in: hosting.bounds, to: rep)
        return rep.representation(using: .png, properties: [:]) ?? Data()
    }

    /// Writes the PNG to `$PINENTRY_RENDER_DIR/<name>.png` when the variable is set.
    func save(named name: String) {
        guard let dir = ProcessInfo.processInfo.environment["PINENTRY_RENDER_DIR"] else { return }
        let url = URL(fileURLWithPath: dir).appendingPathComponent("\(name).png")
        try? FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try? pngData().write(to: url)
    }
}

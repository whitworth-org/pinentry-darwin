// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// RenderSupport — headless rendering of SwiftUI content inside a window that is
// never ordered front, so appearance behaviour can be asserted and inspected
// without putting anything on screen.

import AppKit
import SwiftUI

@MainActor
enum RenderSupport {

    /// Environment values a probe view observed from inside a hosting view.
    struct Observed: Equatable {
        var scheme: ColorScheme?
        var contrast: ColorSchemeContrast?
    }

    final class Box { var value = Observed() }

    struct Probe<Content: View>: View {
        let box: Box
        let content: Content
        @Environment(\.colorScheme) private var scheme
        @Environment(\.colorSchemeContrast) private var contrast

        var body: some View {
            box.value = Observed(scheme: scheme, contrast: contrast)
            return content
        }
    }

    /// Hosts `content` in an off-screen titled window with `appearance` applied to the window.
    static func host<V: View>(
        _ content: V,
        size: NSSize,
        appearance: NSAppearance?
    ) -> (window: NSWindow, view: NSHostingView<V>) {
        let view = NSHostingView(rootView: content)
        let window = NSWindow(
            contentRect: NSRect(origin: .zero, size: size),
            styleMask: [.titled, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        window.isReleasedWhenClosed = false
        window.appearance = appearance
        window.backgroundColor = .windowBackgroundColor
        window.contentView = view
        view.frame = NSRect(origin: .zero, size: size)
        view.layoutSubtreeIfNeeded()
        return (window, view)
    }

    /// Environment values SwiftUI resolves for `appearance` on a hosting view.
    static func observe(appearance: NSAppearance?) -> Observed {
        let box = Box()
        let (window, view) = host(
            Probe(box: box, content: Color.clear.frame(width: 10, height: 10)),
            size: NSSize(width: 40, height: 40),
            appearance: appearance
        )
        view.layoutSubtreeIfNeeded()
        view.displayIfNeeded()
        withExtendedLifetime(window) {}
        return box.value
    }

    /// Renders `content` with ImageRenderer (which, unlike an unshown window, runs
    /// onAppear) in the given scheme. When `PINENTRY_RENDER_DIR` is set the
    /// image is also written there as a PNG. AppKit-backed views do not render this way.
    @discardableResult
    static func render<V: View>(
        _ content: V,
        size: CGSize,
        scheme: ColorScheme,
        name: String
    ) -> NSBitmapImageRep? {
        let framed = content
            .frame(width: size.width, height: size.height, alignment: .topLeading)
            .background(Color(nsColor: .windowBackgroundColor))
            .environment(\.colorScheme, scheme)
        let renderer = ImageRenderer(content: framed)
        renderer.scale = 2
        guard let tiff = renderer.nsImage?.tiffRepresentation,
            let rep = NSBitmapImageRep(data: tiff)
        else { return nil }
        if let dir = ProcessInfo.processInfo.environment["PINENTRY_RENDER_DIR"],
            let data = rep.representation(using: .png, properties: [:])
        {
            let url = URL(fileURLWithPath: dir).appendingPathComponent("\(name).png")
            try? data.write(to: url)
        }
        return rep
    }
}

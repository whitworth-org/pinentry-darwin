#!/usr/bin/env swift
// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// make-icon.swift — generate the .iconset PNG family for pinentry-darwin.
//
// Renders a charcoal squircle with the SF Symbol `lock.shield.fill`
// centered on top, in white with a subtle accent rim. Output goes into
// the directory passed as argv[1] using the canonical icon-file names
// macOS `iconutil` expects:
//
//   icon_16x16.png       icon_16x16@2x.png
//   icon_32x32.png       icon_32x32@2x.png
//   icon_128x128.png     icon_128x128@2x.png
//   icon_256x256.png     icon_256x256@2x.png
//   icon_512x512.png     icon_512x512@2x.png
//
// After generation, the caller runs:
//   iconutil -c icns -o App/Icon.icns <iconset-dir>
//
// Design rationale:
//   - Solid squircle base (corner radius ≈ 22.5% of size) — current macOS
//     icon shape convention.
//   - Charcoal vertical gradient (light at top, near-black at bottom) so
//     the icon reads cleanly on both light Finder backgrounds and dark
//     Dock surfaces without needing appearance variants.
//   - Lock-shield glyph in white, sized to 56% of canvas. White on
//     charcoal is the highest-contrast pairing in the system palette and
//     reads at every scale down to 16pt.
//   - No accent-tinted second glyph, no rim light, no shadow. The skill
//     direction is "refined minimalism with security-craft sensibility";
//     icon clutter would betray that.

import AppKit
import CoreGraphics
import Foundation

let sizes: [(name: String, pixels: Int)] = [
    ("icon_16x16",      16),
    ("icon_16x16@2x",   32),
    ("icon_32x32",      32),
    ("icon_32x32@2x",   64),
    ("icon_128x128",    128),
    ("icon_128x128@2x", 256),
    ("icon_256x256",    256),
    ("icon_256x256@2x", 512),
    ("icon_512x512",    512),
    ("icon_512x512@2x", 1024),
]

func makeContext(pixels: Int) -> CGContext {
    let colorSpace = CGColorSpaceCreateDeviceRGB()
    guard let ctx = CGContext(
        data: nil,
        width: pixels,
        height: pixels,
        bitsPerComponent: 8,
        bytesPerRow: 0,
        space: colorSpace,
        bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue
    ) else {
        fatalError("CGContext init failed for \(pixels)px")
    }
    return ctx
}

func renderIcon(pixels: Int) -> CGImage {
    let ctx = makeContext(pixels: pixels)
    let p = CGFloat(pixels)

    // Squircle path (rounded rect with macOS-style ~22.5% corner radius).
    // The full canvas is filled — macOS does not auto-clip app icons.
    let radius = p * 0.225
    let path = CGPath(
        roundedRect: CGRect(x: 0, y: 0, width: p, height: p),
        cornerWidth: radius,
        cornerHeight: radius,
        transform: nil
    )
    ctx.saveGState()
    ctx.addPath(path)
    ctx.clip()

    // Charcoal vertical gradient. Top is a touch lighter than bottom so
    // the icon reads with subtle dimensionality without resorting to
    // shadows or rim lights.
    let colorSpace = CGColorSpaceCreateDeviceRGB()
    let topColor = CGColor(srgbRed: 0.22, green: 0.22, blue: 0.24, alpha: 1.0)
    let bottomColor = CGColor(srgbRed: 0.06, green: 0.06, blue: 0.07, alpha: 1.0)
    guard let gradient = CGGradient(
        colorsSpace: colorSpace,
        colors: [topColor, bottomColor] as CFArray,
        locations: [0.0, 1.0]
    ) else {
        fatalError("gradient init failed")
    }
    ctx.drawLinearGradient(
        gradient,
        start: CGPoint(x: 0, y: p),
        end: CGPoint(x: 0, y: 0),
        options: []
    )
    ctx.restoreGState()

    // Lock-shield SF Symbol, white, centered, 56% of canvas.
    let symbolPoint = p * 0.56
    let cfg = NSImage.SymbolConfiguration(pointSize: symbolPoint, weight: .semibold)
    guard let raw = NSImage(systemSymbolName: "lock.shield.fill", accessibilityDescription: nil) else {
        fatalError("SF Symbol lock.shield.fill unavailable")
    }
    let symbol = raw.withSymbolConfiguration(cfg) ?? raw

    // Render the symbol into its own bitmap so we can tint it white via
    // sourceAtop without bleeding into the squircle.
    let symW = symbol.size.width
    let symH = symbol.size.height
    let symCtx = makeContext(pixels: max(Int(ceil(max(symW, symH))), 1))
    let nsCtx = NSGraphicsContext(cgContext: symCtx, flipped: false)
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = nsCtx

    let symRect = NSRect(x: 0, y: 0, width: symW, height: symH)
    symbol.draw(
        in: symRect,
        from: .zero,
        operation: .sourceOver,
        fraction: 1.0
    )
    NSColor.white.setFill()
    symRect.fill(using: .sourceAtop)
    NSGraphicsContext.restoreGraphicsState()

    guard let symbolImage = symCtx.makeImage() else {
        fatalError("symbol context image failed")
    }

    // Composite the tinted symbol centered on the canvas.
    let drawX = (p - symW) / 2
    let drawY = (p - symH) / 2
    ctx.draw(symbolImage, in: CGRect(x: drawX, y: drawY, width: symW, height: symH))

    guard let final = ctx.makeImage() else {
        fatalError("final makeImage failed")
    }
    return final
}

func writePNG(_ image: CGImage, to url: URL) throws {
    let rep = NSBitmapImageRep(cgImage: image)
    guard let png = rep.representation(using: .png, properties: [:]) else {
        throw NSError(
            domain: "make-icon",
            code: 1,
            userInfo: [NSLocalizedDescriptionKey: "PNG encoding failed"]
        )
    }
    try png.write(to: url)
}

let args = CommandLine.arguments
guard args.count >= 2 else {
    print("usage: \(args[0]) <output.iconset>")
    exit(2)
}
let iconsetURL = URL(fileURLWithPath: args[1])
try? FileManager.default.createDirectory(at: iconsetURL, withIntermediateDirectories: true)

for (name, px) in sizes {
    let img = renderIcon(pixels: px)
    let url = iconsetURL.appendingPathComponent("\(name).png")
    try writePNG(img, to: url)
    print("wrote \(url.path) (\(px)px)")
}

// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// AboutView.swift — Settings → About tab.

import AppKit
public import SwiftUI

public struct AboutView: View {

    private static let projectURL = URL(string: "https://github.com/whitworth-org/pinentry-darwin")!

    public init() {}

    private var version: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0.0.0"
    }

    private var build: String {
        Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "0"
    }

    public var body: some View {
        VStack(spacing: Theme.mediumPadding) {
            Spacer(minLength: 0)
            Image(nsImage: NSApplication.shared.applicationIconImage)
                .resizable()
                .aspectRatio(contentMode: .fit)
                .frame(width: 96, height: 96)
                .accessibilityHidden(true)

            VStack(spacing: Theme.smallPadding / 2) {
                Text("pinentry-darwin")
                    .font(.title.weight(.semibold))
                Text("Version \(version) (\(build))")
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }
            .accessibilityElement(children: .combine)

            Link("github.com/whitworth-org/pinentry-darwin", destination: Self.projectURL)
                .accessibilityLabel("Project page on GitHub")

            VStack(spacing: Theme.smallPadding / 2) {
                Text("Window styling derived from Ghostty (MIT).")
                Text("Compatible with the GnuPG pinentry Assuan protocol.")
                Text("MIT licensed. Copyright © 2026 Ryan Whitworth.")
            }
            .font(.caption)
            .foregroundStyle(.secondary)
            .multilineTextAlignment(.center)
            Spacer(minLength: 0)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding(Theme.blockPadding)
    }
}

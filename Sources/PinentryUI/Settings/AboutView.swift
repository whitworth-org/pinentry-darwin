// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// AboutView.swift — Settings → About tab.
//
// The build hash is shown as "dev" until a generated source file with a
// `BUILD_HASH` constant is added at build time. Doing this without a
// build script is out of scope for this module.

import SwiftUI

public struct AboutView: View {

    public init() {}

    private var version: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0.0.0"
    }

    private var build: String {
        Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "0"
    }

    private var buildHash: String { "dev" }

    public var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Theme.mediumPadding) {
                HStack(spacing: Theme.mediumPadding) {
                    // Asset is referenced by name; bundle may not yet ship one.
                    // SwiftUI silently renders an empty image if missing.
                    Image("AppIcon")
                        .resizable()
                        .aspectRatio(contentMode: .fit)
                        .frame(width: 64, height: 64)

                    VStack(alignment: .leading, spacing: Theme.smallPadding / 2) {
                        Text("pinentry-darwin")
                            .font(Theme.titleFont)
                            .fontWeight(.bold)
                            .foregroundStyle(Color.primary)
                        Text("Version \(version) (\(build))")
                            .font(Theme.bodyFont)
                            .foregroundStyle(Color.secondary)
                        Text("Build \(buildHash)")
                            .font(Theme.monospacedFont)
                            .foregroundStyle(Color.secondary)
                    }
                }

                Divider()

                Text("MIT licensed")
                    .font(Theme.bodyFont)
                    .foregroundStyle(Color.primary)

                Link(
                    "github.com/whitworth-org/pinentry-darwin",
                    destination: URL(string: "https://github.com/whitworth-org/pinentry-darwin")!
                )
                .font(Theme.bodyFont)

                Divider()

                VStack(alignment: .leading, spacing: Theme.smallPadding) {
                    Text("Attributions")
                        .font(Theme.bodyFont)
                        .fontWeight(.semibold)
                        .foregroundStyle(Color.primary)
                    Text("Window styling derived from Ghostty (MIT).")
                        .font(Theme.captionFont)
                        .foregroundStyle(Color.secondary)
                    Text("Assuan protocol surface compatible with GnuPG pinentry.")
                        .font(Theme.captionFont)
                        .foregroundStyle(Color.secondary)
                }
            }
            .padding(Theme.mediumPadding)
            .frame(maxWidth: .infinity, alignment: .leading)
            .textSelection(.enabled)
        }
    }
}

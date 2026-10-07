// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// PerKeyPolicyControls.swift — subviews and copy shared by the per-key
// policy tab: the three policy pickers and the key row label.

import AppKit
import KeychainStore
import SwiftUI

/// Plain-language names for the policy fields.
enum KeyPolicyText {

    static let cacheChoices: [(seconds: Int, title: String)] = [
        (0, "Until cleared"),
        (5 * 60, "5 minutes"),
        (60 * 60, "1 hour"),
        (8 * 60 * 60, "8 hours"),
        (24 * 60 * 60, "1 day"),
    ]

    static func title(_ value: KeyPolicy.BiometryRequirement) -> String {
        switch value {
        case .userPresence: "Touch ID or password"
        case .biometryCurrentSet: "Touch ID, current fingerprints only"
        case .biometryAny: "Touch ID, any enrolled fingerprint"
        case .devicePasscode: "Password only"
        }
    }

    static func title(_ value: KeyPolicy.Accessibility) -> String {
        switch value {
        case .whenUnlocked: "When the Mac is unlocked"
        case .whenPasscodeSet: "Only while a password is set"
        }
    }

    /// The standard durations, plus `current` when it is not one of them.
    static func cacheOptions(including current: Int) -> [Int] {
        let standard = cacheChoices.map(\.seconds)
        return standard.contains(current) ? standard : (standard + [current]).sorted()
    }

    static func cacheTitle(_ seconds: Int) -> String {
        if let known = cacheChoices.first(where: { $0.seconds == seconds }) {
            return known.title
        }
        guard seconds % 60 == 0 else { return "\(seconds) seconds" }
        return seconds == 60 ? "1 minute" : "\(seconds / 60) minutes"
    }

    /// One line such as "Touch ID or password · 1 hour".
    static func summary(_ policy: KeyPolicy) -> String {
        [title(policy.biometry), cacheTitle(policy.cacheTTLSeconds ?? 0)].joined(separator: " · ")
    }
}

/// The authentication, availability, and cache-duration pickers for one policy.
struct PolicyControls: View {

    let policy: KeyPolicy
    let onChange: (KeyPolicy) -> Void

    var body: some View {
        Picker("Authentication", selection: biometry) {
            ForEach(KeyPolicy.BiometryRequirement.allCases, id: \.self) {
                Text(KeyPolicyText.title($0)).tag($0)
            }
        }
        Picker("Availability", selection: accessibility) {
            ForEach(KeyPolicy.Accessibility.allCases, id: \.self) {
                Text(KeyPolicyText.title($0)).tag($0)
            }
        }
        Picker("Cache duration", selection: cacheSeconds) {
            ForEach(cacheOptions, id: \.self) { Text(KeyPolicyText.cacheTitle($0)).tag($0) }
        }
    }

    private var cacheOptions: [Int] {
        KeyPolicyText.cacheOptions(including: policy.cacheTTLSeconds ?? 0)
    }

    private var biometry: Binding<KeyPolicy.BiometryRequirement> {
        Binding(
            get: { policy.biometry },
            set: {
                onChange(KeyPolicy(
                    biometry: $0,
                    accessibility: policy.accessibility,
                    cacheTTLSeconds: policy.cacheTTLSeconds
                ))
            }
        )
    }

    private var accessibility: Binding<KeyPolicy.Accessibility> {
        Binding(
            get: { policy.accessibility },
            set: {
                onChange(KeyPolicy(
                    biometry: policy.biometry,
                    accessibility: $0,
                    cacheTTLSeconds: policy.cacheTTLSeconds
                ))
            }
        )
    }

    private var cacheSeconds: Binding<Int> {
        Binding(
            get: { policy.cacheTTLSeconds ?? 0 },
            set: {
                onChange(KeyPolicy(
                    biometry: policy.biometry,
                    accessibility: policy.accessibility,
                    cacheTTLSeconds: $0 == 0 ? nil : $0
                ))
            }
        )
    }
}

/// Collapsed content of a key row: abbreviated fingerprint and policy state.
struct KeyRowLabel: View {

    let row: PerKeyPolicyModel.Row

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(spacing: Theme.smallPadding) {
                Text(KeyIdentifier.abbreviated(row.fingerprint))
                    .font(.system(.body, design: .monospaced))
                    .lineLimit(1)
                    .truncationMode(.middle)
                if row.hasOverride {
                    SettingsBadge(
                        title: "Custom policy",
                        systemImage: "slider.horizontal.3",
                        tint: Theme.accent
                    )
                }
            }
            Text(row.hasOverride
                ? KeyPolicyText.summary(row.policy)
                : "Uses default · \(KeyPolicyText.summary(row.policy))")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Key \(KeyIdentifier.grouped(row.fingerprint))")
        .accessibilityValue(
            row.hasOverride
                ? "Custom policy. \(KeyPolicyText.summary(row.policy))"
                : "Uses default policy. \(KeyPolicyText.summary(row.policy))"
        )
    }
}

/// Clipboard writes for non-secret identifiers (fingerprints, hashes, commands).
enum Pasteboard {
    static func copy(_ text: String) {
        let board = NSPasteboard.general
        board.clearContents()
        board.setString(text, forType: .string)
    }
}

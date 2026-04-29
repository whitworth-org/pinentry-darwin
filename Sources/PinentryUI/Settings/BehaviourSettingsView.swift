// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// BehaviourSettingsView.swift — Settings → Behaviour tab.

import SwiftUI

public struct BehaviourSettingsView: View {
    @Binding public var settings: UISettings
    public let onChange: (UISettings) -> Void

    public init(
        settings: Binding<UISettings>,
        onChange: @escaping (UISettings) -> Void
    ) {
        self._settings = settings
        self.onChange = onChange
    }

    public var body: some View {
        Form {
            Section("Timeout") {
                // 0 disables the timeout entirely.
                Stepper(
                    value: $settings.defaultTimeout,
                    in: 0...600,
                    step: 5
                ) {
                    if settings.defaultTimeout == 0 {
                        Text("Default timeout: never")
                    } else {
                        Text("Default timeout: \(settings.defaultTimeout)s")
                    }
                }
                .onChange(of: settings.defaultTimeout) { _, _ in onChange(settings) }
            }

            Section("Window") {
                Toggle("Close on focus loss", isOn: $settings.closeOnBlur)
                    .onChange(of: settings.closeOnBlur) { _, _ in onChange(settings) }
            }

            Section("Feedback") {
                Toggle("Beep on weak passphrase", isOn: $settings.beepOnWeakPassphrase)
                    .onChange(of: settings.beepOnWeakPassphrase) { _, _ in onChange(settings) }
            }
        }
        .padding(Theme.mediumPadding)
    }
}

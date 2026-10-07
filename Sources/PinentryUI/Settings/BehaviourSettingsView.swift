// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// BehaviourSettingsView.swift — Settings → Behaviour tab.

public import SwiftUI

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
                Text("Used when gpg-agent does not request a timeout of its own.")
                    .font(Theme.captionFont)
                    .foregroundStyle(Color.secondary)
            }

            Section("Security") {
                Text(
                    "Secure keyboard entry is always on while a passphrase dialog is open. "
                        + "Keystrokes take a path other apps cannot observe, and macOS shows "
                        + "a lock badge in the menu bar."
                )
                    .font(Theme.captionFont)
                    .foregroundStyle(Color.secondary)
                    .fixedSize(horizontal: false, vertical: true)

                Toggle("Clear clipboard after paste", isOn: $settings.clearPasteboardOnSubmit)
                    .onChange(of: settings.clearPasteboardOnSubmit) { _, _ in onChange(settings) }
                Text("If you paste a passphrase into the dialog, clear the system clipboard on submit so the cleartext doesn't linger. Detected via clipboard change-count; the contents are never inspected.")
                    .font(Theme.captionFont)
                    .foregroundStyle(Color.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}

// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// SettingsView.swift — the root TabView for the `--preferences` mode.
// Hosted by the executable when invoked with the preferences flag.

import SwiftUI
import KeychainStore

public struct SettingsRootView: View {

    @State private var uiSettings: UISettings
    @State private var keychainPrefs: UserPrefs

    /// Optional closure to clear all stored passphrases. Wired up by the
    /// executable (KeychainStore.clearAll). nil shows "Coming soon".
    private let clearAllPassphrases: (@Sendable () async -> Void)?

    /// Optional closure to forget a single stored passphrase by
    /// fingerprint. Wired up by the executable (KeychainStore.clear).
    /// nil disables the per-row Forget button in PerKeyPolicyView.
    private let forgetPassphrase: (@Sendable (String) async -> Void)?

    /// Optional persistence hook. The executable typically passes a
    /// closure that calls `await UISettingsStore().save(_:)`.
    private let saveUI: (@Sendable (UISettings) -> Void)?

    public init(
        uiSettings: UISettings = UISettings(),
        keychainPrefs: UserPrefs = UserPrefs(),
        clearAllPassphrases: (@Sendable () async -> Void)? = nil,
        forgetPassphrase: (@Sendable (String) async -> Void)? = nil,
        saveUI: (@Sendable (UISettings) -> Void)? = nil
    ) {
        self._uiSettings = State(initialValue: uiSettings)
        self._keychainPrefs = State(initialValue: keychainPrefs)
        self.clearAllPassphrases = clearAllPassphrases
        self.forgetPassphrase = forgetPassphrase
        self.saveUI = saveUI
    }

    public var body: some View {
        TabView {
            AppearanceSettingsView(
                settings: $uiSettings,
                keychainPrefs: $keychainPrefs,
                onChange: { saveUI?($0) }
            )
            .tabItem { Label("Appearance", systemImage: "paintbrush") }

            KeychainSettingsView(
                keychainPrefs: $keychainPrefs,
                clearAll: clearAllPassphrases
            )
            .tabItem { Label("Keychain", systemImage: "key") }

            PerKeyPolicyView(forget: forgetPassphrase)
                .tabItem { Label("Per-Key", systemImage: "person.badge.key") }

            BehaviourSettingsView(
                settings: $uiSettings,
                onChange: { saveUI?($0) }
            )
            .tabItem { Label("Behaviour", systemImage: "slider.horizontal.3") }

            AboutView()
                .tabItem { Label("About", systemImage: "info.circle") }
        }
        .frame(minWidth: 520, minHeight: 360)
        .padding(Theme.mediumPadding)
    }
}

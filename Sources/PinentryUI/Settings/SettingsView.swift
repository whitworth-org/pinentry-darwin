// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// SettingsView.swift — the root TabView for the `--preferences` mode.
// Hosted by the executable when invoked with the preferences flag.

public import SwiftUI
public import KeychainStore

public struct SettingsRootView: View {

    @State private var uiSettings: UISettings
    @State private var keychainPrefs: UserPrefs
    @State private var selection: SettingsTab

    /// Optional closure to clear all stored passphrases. Wired up by the
    /// executable. Throws if any delete failed. nil hides the Maintenance
    /// section in the Keychain tab.
    private let clearAllPassphrases: (@concurrent @Sendable () async throws -> Void)?

    /// Optional closure to forget a single stored passphrase by
    /// fingerprint. Wired up by the executable (KeychainStore.clear).
    /// Throws if the delete failed. nil hides the per-row Forget action in
    /// PerKeyPolicyView.
    private let forgetPassphrase: PerKeyPolicyView.ForgetCallback?

    /// Optional persistence hook. The executable typically passes a
    /// closure that calls `await UISettingsStore().save(_:)`.
    private let saveUI: (@Sendable (UISettings) -> Void)?

    public init(
        uiSettings: UISettings = UISettings(),
        keychainPrefs: UserPrefs = UserPrefs(),
        clearAllPassphrases: (@concurrent @Sendable () async throws -> Void)? = nil,
        forgetPassphrase: PerKeyPolicyView.ForgetCallback? = nil,
        saveUI: (@Sendable (UISettings) -> Void)? = nil
    ) {
        self.init(
            uiSettings: uiSettings,
            keychainPrefs: keychainPrefs,
            clearAllPassphrases: clearAllPassphrases,
            forgetPassphrase: forgetPassphrase,
            saveUI: saveUI,
            selection: .appearance
        )
    }

    init(
        uiSettings: UISettings,
        keychainPrefs: UserPrefs,
        clearAllPassphrases: (@concurrent @Sendable () async throws -> Void)?,
        forgetPassphrase: PerKeyPolicyView.ForgetCallback?,
        saveUI: (@Sendable (UISettings) -> Void)?,
        selection: SettingsTab
    ) {
        self._selection = State(initialValue: selection)
        self._uiSettings = State(initialValue: uiSettings)
        self._keychainPrefs = State(initialValue: keychainPrefs)
        self.clearAllPassphrases = clearAllPassphrases
        self.forgetPassphrase = forgetPassphrase
        self.saveUI = saveUI
    }

    public var body: some View {
        content
            .formStyle(.grouped)
            .frame(
                minWidth: SettingsLayout.minWidth,
                idealWidth: SettingsLayout.idealWidth,
                minHeight: SettingsLayout.minHeight,
                idealHeight: SettingsLayout.idealHeight
            )
            .background(SettingsToolbarInstaller(selection: $selection))
    }

    @ViewBuilder
    private var content: some View {
        switch selection {
        case .appearance:
            AppearanceSettingsView(
                settings: $uiSettings,
                keychainPrefs: $keychainPrefs,
                onChange: { saveUI?($0) }
            )
        case .behaviour:
            BehaviourSettingsView(settings: $uiSettings, onChange: { saveUI?($0) })
        case .keychain:
            KeychainSettingsView(keychainPrefs: $keychainPrefs, clearAll: clearAllPassphrases)
        case .perKey:
            PerKeyPolicyView(forget: forgetPassphrase)
        case .ssh:
            SSHIdentitiesView()
        case .about:
            AboutView()
        }
    }
}

/// One size for every tab so the window never resizes when switching.
enum SettingsLayout {
    static let minWidth: CGFloat = 560
    static let idealWidth: CGFloat = 600
    static let minHeight: CGFloat = 440
    static let idealHeight: CGFloat = 520
}

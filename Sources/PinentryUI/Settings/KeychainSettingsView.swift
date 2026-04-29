// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// KeychainSettingsView.swift — Settings → Keychain tab.

import SwiftUI
import KeychainStore

public struct KeychainSettingsView: View {
    @Binding public var keychainPrefs: UserPrefs
    public let clearAll: (@Sendable () async -> Void)?

    @State private var showClearConfirmation = false
    @State private var isClearing = false

    public init(
        keychainPrefs: Binding<UserPrefs>,
        clearAll: (@Sendable () async -> Void)? = nil
    ) {
        self._keychainPrefs = keychainPrefs
        self.clearAll = clearAll
    }

    public var body: some View {
        Form {
            Section("Master") {
                Toggle("Use macOS Keychain", isOn: Binding(
                    get: { keychainPrefs.keychainEnabled },
                    set: { newValue in
                        var copy = keychainPrefs
                        copy.set(keychainEnabled: newValue)
                        keychainPrefs = copy
                    }
                ))
            }

            Section("Defaults") {
                Toggle("Save passphrases by default", isOn: Binding(
                    get: { keychainPrefs.saveByDefault },
                    set: { newValue in
                        var copy = keychainPrefs
                        copy.set(saveByDefault: newValue)
                        keychainPrefs = copy
                    }
                ))
                .disabled(!keychainPrefs.keychainEnabled)
            }

            Section("Maintenance") {
                Button(role: .destructive) {
                    if clearAll != nil {
                        showClearConfirmation = true
                    }
                } label: {
                    Text("Forget all stored passphrases")
                        .foregroundStyle(clearAll == nil ? Color.secondary : Theme.errorText)
                }
                .disabled(clearAll == nil || isClearing)

                if clearAll == nil {
                    Text("Coming soon")
                        .font(Theme.captionFont)
                        .foregroundStyle(Color.secondary)
                }
            }
        }
        .padding(Theme.mediumPadding)
        .alert(
            "Forget all stored passphrases?",
            isPresented: $showClearConfirmation
        ) {
            Button("Cancel", role: .cancel) {}
            Button("Forget All", role: .destructive) {
                guard let clearAll else { return }
                isClearing = true
                Task { @MainActor in
                    await clearAll()
                    isClearing = false
                }
            }
        } message: {
            Text("This removes every entry pinentry-darwin has saved in the macOS Keychain. GPG will prompt for each passphrase the next time it is needed.")
        }
    }
}

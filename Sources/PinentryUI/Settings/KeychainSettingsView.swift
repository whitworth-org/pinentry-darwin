// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// KeychainSettingsView.swift — Settings → Keychain tab.

public import KeychainStore
public import SwiftUI

/// Runs the Forget-all action and records the outcome for the view.
@MainActor
@Observable
final class ForgetAllModel {

    typealias Action = @concurrent @Sendable () async throws -> Void

    private(set) var isRunning = false
    private(set) var notice: String?
    var errorMessage: String?

    func run(_ action: Action) async {
        guard !isRunning else { return }
        isRunning = true
        notice = nil
        errorMessage = nil
        defer { isRunning = false }
        do {
            try await action()
            notice = "All saved passphrases were removed."
        } catch {
            errorMessage = "Could not forget all saved passphrases. "
                + SavedPassphrases.failureReason(for: error)
        }
    }
}

public struct KeychainSettingsView: View {
    @Binding public var keychainPrefs: UserPrefs
    public let clearAll: (@concurrent @Sendable () async throws -> Void)?

    @State private var showClearConfirmation = false
    @State private var model = ForgetAllModel()

    public init(
        keychainPrefs: Binding<UserPrefs>,
        clearAll: (@concurrent @Sendable () async throws -> Void)? = nil
    ) {
        self._keychainPrefs = keychainPrefs
        self.clearAll = clearAll
    }

    public var body: some View {
        Form {
            if let message = model.errorMessage {
                Section {
                    SettingsBanner(kind: .error, message: message) { model.errorMessage = nil }
                }
            }
            masterSection
            defaultsSection
            if clearAll != nil { maintenanceSection }
        }
        .formStyle(.grouped)
        .alert("Forget all saved passphrases?", isPresented: $showClearConfirmation) {
            Button("Forget all", role: .destructive) {
                guard let clearAll else { return }
                Task { await model.run(clearAll) }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(
                "This removes every passphrase pinentry-darwin has saved in the Keychain. "
                    + "GnuPG asks for each one again when it is next needed."
            )
        }
    }

    // MARK: - Sections

    private var masterSection: some View {
        Section {
            Toggle("Use the macOS Keychain", isOn: prefBinding(
                get: { $0.keychainEnabled },
                set: { $0.set(keychainEnabled: $1) }
            ))
        } footer: {
            Text("When off, passphrase dialogs do not offer Save in Keychain.")
        }
    }

    private var defaultsSection: some View {
        Section {
            Toggle("Save passphrases by default", isOn: prefBinding(
                get: { $0.saveByDefault },
                set: { $0.set(saveByDefault: $1) }
            ))
            .disabled(!keychainPrefs.keychainEnabled)
        } footer: {
            Text("Ticks Save in Keychain when a passphrase dialog opens.")
        }
    }

    private var maintenanceSection: some View {
        Section {
            HStack {
                Button("Forget all saved passphrases…", role: .destructive) {
                    showClearConfirmation = true
                }
                .foregroundStyle(Theme.errorText)
                .disabled(model.isRunning)
                if model.isRunning {
                    ProgressView().controlSize(.small)
                }
            }
        } footer: {
            Text(model.notice ?? "Removes every saved passphrase and its per-key policy.")
        }
    }

    private func prefBinding(
        get: @escaping (UserPrefs) -> Bool,
        set: @escaping (inout UserPrefs, Bool) -> Void
    ) -> Binding<Bool> {
        Binding(
            get: { get(keychainPrefs) },
            set: { newValue in
                var copy = keychainPrefs
                set(&copy, newValue)
                keychainPrefs = copy
            }
        )
    }
}

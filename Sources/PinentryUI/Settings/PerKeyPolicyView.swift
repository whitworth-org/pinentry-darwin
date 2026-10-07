// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// PerKeyPolicyView.swift — Settings → Per-key policy tab.
//
// Lists each key that has a saved passphrase in the data-protection
// Keychain, plus a default policy for new keys. Each key row expands to
// the same three controls (authentication, availability, cache duration),
// "Reset to default", and "Forget passphrase…".
//
// Enumeration uses `kSecUseAuthenticationUISkip`, so opening Settings
// never shows a Touch ID sheet. Policy changes are written immediately;
// there is no Save button.

public import KeychainStore
public import SwiftUI

public struct PerKeyPolicyView: View {

    /// Deletes the Keychain entry for a fingerprint. Provided by the
    /// executable so the view needs no clear-by-fingerprint API. Throws if
    /// the delete failed, in which case the view keeps the key's policy.
    /// nil hides the Forget action.
    public typealias ForgetCallback = @concurrent @Sendable (String) async throws -> Void

    @State private var model: PerKeyPolicyModel
    @State private var expanded: Set<String>
    @State private var pendingForget: String?

    public init(
        store: KeyPolicyStore = KeyPolicyStore(),
        service: String = "GnuPG",
        useDataProtectionKeychain: Bool = true,
        forget: ForgetCallback? = nil
    ) {
        self.init(
            model: PerKeyPolicyModel(
                store: store,
                enumerate: {
                    KeychainEnumerator.fingerprints(
                        service: service,
                        useDataProtectionKeychain: useDataProtectionKeychain
                    )
                },
                forget: forget
            )
        )
    }

    init(model: PerKeyPolicyModel, expanded: Set<String> = []) {
        self._model = State(initialValue: model)
        self._expanded = State(initialValue: expanded)
    }

    public var body: some View {
        Form {
            if let message = model.errorMessage {
                Section {
                    SettingsBanner(kind: .error, message: message) { model.errorMessage = nil }
                }
            }
            defaultSection
            savedKeysSection
        }
        .formStyle(.grouped)
        .task { await model.load() }
        .confirmationDialog(
            "Forget the saved passphrase?",
            isPresented: Binding(
                get: { pendingForget != nil },
                set: { if !$0 { pendingForget = nil } }
            ),
            titleVisibility: .visible,
            presenting: pendingForget
        ) { fingerprint in
            Button("Forget passphrase", role: .destructive) {
                Task { await model.forget(fingerprint) }
            }
            Button("Cancel", role: .cancel) {}
        } message: { fingerprint in
            Text(
                "\(KeyIdentifier.abbreviated(fingerprint)) is removed from the Keychain "
                    + "along with its policy. GnuPG asks for the passphrase next time."
            )
        }
    }

    // MARK: - Sections

    private var defaultSection: some View {
        Section {
            PolicyControls(policy: model.defaultPolicy, onChange: model.setDefault)
        } header: {
            Text("Default for new keys")
        } footer: {
            Text("Used when you choose Save in Keychain for a key without its own policy.")
        }
    }

    private var savedKeysSection: some View {
        Section {
            switch model.phase {
            case .loading:
                HStack(spacing: Theme.smallPadding) {
                    ProgressView().controlSize(.small)
                    Text("Loading saved keys…").foregroundStyle(.secondary)
                }
                .accessibilityElement(children: .combine)
            case .loaded where model.rows.isEmpty:
                Text("No saved passphrases. Choose Save in Keychain in a passphrase dialog "
                    + "and the key appears here.")
                    .foregroundStyle(.secondary)
            case .loaded:
                ForEach(model.rows) { row in keyRow(row) }
            }
        } header: {
            Text("Saved keys")
        }
    }

    // MARK: - Key row

    private func keyRow(_ row: PerKeyPolicyModel.Row) -> some View {
        DisclosureGroup(isExpanded: expansion(for: row.fingerprint)) {
            PolicyControls(
                policy: row.policy,
                onChange: { model.setPolicy($0, for: row.fingerprint) }
            )
            rowActions(row)
        } label: {
            KeyRowLabel(row: row)
        }
        .contextMenu {
            Button("Copy fingerprint") { Pasteboard.copy(row.fingerprint.uppercased()) }
            if row.hasOverride {
                Button("Reset to default") { model.resetOverride(for: row.fingerprint) }
            }
            if model.canForget {
                Button("Forget passphrase…", role: .destructive) {
                    pendingForget = row.fingerprint
                }
                .disabled(model.forgetting != nil)
            }
        }
    }

    @ViewBuilder
    private func rowActions(_ row: PerKeyPolicyModel.Row) -> some View {
        LabeledContent("Fingerprint") {
            Text(KeyIdentifier.grouped(row.fingerprint))
                .font(.system(.caption, design: .monospaced))
                .textSelection(.enabled)
                .multilineTextAlignment(.trailing)
        }
        HStack {
            if row.hasOverride {
                Button("Reset to default") { model.resetOverride(for: row.fingerprint) }
            }
            Spacer()
            if model.canForget {
                Button("Forget passphrase…", role: .destructive) {
                    pendingForget = row.fingerprint
                }
                .foregroundStyle(Theme.errorText)
                .disabled(model.forgetting != nil)
            }
        }
    }

    private func expansion(for fingerprint: String) -> Binding<Bool> {
        Binding(
            get: { expanded.contains(fingerprint) },
            set: { isOpen in
                if isOpen { expanded.insert(fingerprint) } else { expanded.remove(fingerprint) }
            }
        )
    }
}

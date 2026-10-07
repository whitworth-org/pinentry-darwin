// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// SSHIdentitiesView.swift — Settings → SSH tab. Wraps
// `sc_auth create-ctk-identity` / `delete-ctk-identity` and `ssh-add
// -K -S /usr/lib/ssh-keychain.dylib` so the user can manage
// Secure-Enclave-backed SSH keys without leaving the app.
//
// The actual sc_auth / ssh-add subprocess work lives in the
// `SSHIdentity` library; this view is a thin SwiftUI shell that binds
// to its `@MainActor ObservableObject` and surfaces errors via
// `manager.lastError`. Touch ID is owned by the OS during the
// underlying `sc_auth create-ctk-identity -t bio` invocation; we
// just await the subprocess.

import SSHIdentity
public import SwiftUI

public struct SSHIdentitiesView: View {

    private static let shellExport = "export SSH_SK_PROVIDER=/usr/lib/ssh-keychain.dylib"

    @StateObject private var manager: SSHIdentityManager
    @State private var newLabel = "ssh"
    @State private var showAll = false
    @State private var hasLoaded = false
    @State private var pendingDelete: CTKIdentity?

    public init() {
        self.init(manager: SSHIdentityManager())
    }

    init(manager: @autoclosure @escaping @MainActor () -> SSHIdentityManager) {
        self._manager = StateObject(wrappedValue: manager())
    }

    public var body: some View {
        Form {
            notices
            identitiesSection
            createSection
            agentSection
            shellSection
        }
        .formStyle(.grouped)
        .alert(
            "Delete this identity?",
            isPresented: Binding(
                get: { pendingDelete != nil },
                set: { if !$0 { pendingDelete = nil } }
            ),
            presenting: pendingDelete
        ) { identity in
            Button("Delete", role: .destructive) {
                Task { await manager.delete(identity) }
            }
            Button("Cancel", role: .cancel) {}
        } message: { identity in
            Text(
                "The Secure Enclave key \"\(identity.label)\" is removed and cannot be "
                    + "recovered. Anything that authenticates with it stops working."
            )
        }
        .task {
            await manager.refresh()
            hasLoaded = true
        }
    }

    // MARK: - Sections

    @ViewBuilder
    private var notices: some View {
        if let error = manager.lastError {
            Section {
                SettingsBanner(kind: .error, message: error, onDismiss: manager.dismissError)
            }
        }
        if let warning = manager.lastWarning {
            Section {
                SettingsBanner(kind: .warning, message: warning, onDismiss: manager.dismissWarning)
            }
        }
    }

    private var identitiesSection: some View {
        Section {
            if !hasLoaded {
                HStack(spacing: Theme.smallPadding) {
                    ProgressView().controlSize(.small)
                    Text("Loading identities…").foregroundStyle(.secondary)
                }
                .accessibilityElement(children: .combine)
            } else if visibleIdentities.isEmpty {
                Text(emptyMessage).foregroundStyle(.secondary)
            }
            ForEach(visibleIdentities) { identity in
                SSHIdentityRow(
                    identity: identity,
                    isBusy: manager.isBusy,
                    onDelete: { pendingDelete = identity }
                )
            }
            Toggle("Include identities without an ssh label", isOn: $showAll)
        } header: {
            Text("Secure Enclave identities")
        }
    }

    private var createSection: some View {
        Section {
            TextField("Label", text: $newLabel)
                .onSubmit(create)
            HStack {
                Button("Create with Touch ID…", action: create)
                    .disabled(!canCreate)
                if manager.isBusy && hasLoaded {
                    ProgressView().controlSize(.small)
                }
            }
        } header: {
            Text("New identity")
        } footer: {
            Text(labelHint).foregroundStyle(labelIsInvalid ? Theme.errorText : .secondary)
        }
    }

    private var agentSection: some View {
        Section {
            Button("Add Secure Enclave keys to ssh-agent") {
                Task { await manager.registerWithAgent() }
            }
            .disabled(manager.isBusy)
            if hasLoaded && manager.agentKeys.isEmpty {
                Text("ssh-agent has no keys loaded.").foregroundStyle(.secondary)
            }
            ForEach(manager.agentKeys) { SSHAgentKeyRow(key: $0) }
        } header: {
            Text("ssh-agent")
        }
    }

    private var shellSection: some View {
        Section {
            LabeledContent {
                Button {
                    Pasteboard.copy(Self.shellExport)
                } label: {
                    Image(systemName: "doc.on.doc")
                }
                .buttonStyle(.borderless)
                .help("Copy command")
                .accessibilityLabel("Copy command")
            } label: {
                Text(Self.shellExport)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
            }
        } header: {
            Text("Shell setup")
        } footer: {
            Text("Add this line to your shell profile so ssh, ssh-add, and ssh-keygen use the "
                + "Secure Enclave by default.")
        }
    }

    // MARK: - Derived state

    private var visibleIdentities: [CTKIdentity] {
        showAll ? manager.identities : manager.identities.filter(\.isSSHLabelled)
    }

    private var emptyMessage: String {
        if manager.lastError != nil && manager.identities.isEmpty {
            return "Identities could not be loaded."
        }
        return manager.identities.isEmpty
            ? "No Secure Enclave identities."
            : "No identities with an ssh label. Turn on the option below to see the rest."
    }

    private var labelIsInvalid: Bool { !newLabel.isEmpty && !validateLabel(newLabel) }

    private var canCreate: Bool { validateLabel(newLabel) && !manager.isBusy }

    private var labelHint: String {
        labelIsInvalid
            ? "Use 1 to 64 letters, digits, dots, underscores, or hyphens."
            : "Start the label with ssh to list the identity here. Use 1 to 64 letters, "
                + "digits, dots, underscores, or hyphens."
    }

    private func create() {
        guard canCreate else { return }
        let label = newLabel
        Task { await manager.create(label: label) }
    }
}

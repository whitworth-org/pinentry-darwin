// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// SSHIdentitiesView.swift — Settings → SSH Identities tab. Wraps
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

import SwiftUI
import SSHIdentity

@available(macOS 26.0, *)
public struct SSHIdentitiesView: View {

    @StateObject private var manager = SSHIdentityManager()
    @State private var newLabel = "ssh"
    @State private var showAll = false
    @State private var pendingDelete: CTKIdentity?

    public init() {}

    public var body: some View {
        Form {
            if let error = manager.lastError {
                Section {
                    HStack(alignment: .top, spacing: Theme.smallPadding) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundStyle(Theme.errorText)
                        Text(error)
                            .font(Theme.captionFont)
                            .textSelection(.enabled)
                        Spacer()
                        Button("Dismiss") { manager.dismissError() }
                            .controlSize(.small)
                    }
                }
            }

            Section("Existing identities") {
                if filteredIdentities.isEmpty {
                    Text(manager.identities.isEmpty
                         ? "No Secure-Enclave SSH identities yet."
                         : "No identities matching the current filter.")
                        .font(Theme.captionFont)
                        .foregroundStyle(.secondary)
                }
                ForEach(filteredIdentities) { identity in
                    identityRow(identity)
                }
                Toggle("Show all CTK identities", isOn: $showAll)
                    .controlSize(.small)
                    .padding(.top, Theme.smallPadding)
            }

            Section("Create new identity") {
                HStack {
                    TextField("Label", text: $newLabel)
                        .textFieldStyle(.roundedBorder)
                    Button("Create with Touch ID…") {
                        Task { @MainActor in await manager.create(label: newLabel) }
                    }
                    .disabled(manager.isBusy || newLabel.isEmpty)
                }
                Text("Allowed: A-Z, a-z, 0-9, dot, underscore, hyphen, 1-64 chars.")
                    .font(Theme.captionFont)
                    .foregroundStyle(.secondary)
            }

            Section("Register with ssh-agent") {
                Button("Add Secure-Enclave keys to ssh-agent") {
                    Task { @MainActor in await manager.registerWithAgent() }
                }
                .disabled(manager.isBusy)

                if manager.agentKeys.isEmpty {
                    Text("ssh-agent has no identities.")
                        .font(Theme.captionFont)
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(manager.agentKeys) { key in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(key.keyType)
                                .font(Theme.captionFont)
                                .foregroundStyle(.secondary)
                            Text(key.rawLine)
                                .font(.system(.caption, design: .monospaced))
                                .textSelection(.enabled)
                                .lineLimit(2)
                                .truncationMode(.middle)
                        }
                        .padding(.vertical, 2)
                    }
                }
            }

            Section("Use in your shell") {
                VStack(alignment: .leading, spacing: Theme.smallPadding) {
                    Text("Add this to your shell profile so ssh, ssh-add, and ssh-keygen all use the Secure Enclave by default:")
                        .font(Theme.captionFont)
                        .foregroundStyle(.secondary)
                    Text("export SSH_SK_PROVIDER=/usr/lib/ssh-keychain.dylib")
                        .font(.system(.body, design: .monospaced))
                        .textSelection(.enabled)
                        .padding(Theme.smallPadding)
                        .background(Color(NSColor.controlBackgroundColor))
                        .cornerRadius(4)
                }
            }
        }
        .padding(Theme.mediumPadding)
        .alert(item: $pendingDelete) { identity in
            Alert(
                title: Text("Delete identity \"\(identity.label)\"?"),
                message: Text("This removes the Secure-Enclave-backed key with hash \(identity.publicKeyHash.prefix(16))… and cannot be undone."),
                primaryButton: .destructive(Text("Delete")) {
                    Task { @MainActor in await manager.delete(identity) }
                },
                secondaryButton: .cancel()
            )
        }
        .task { await manager.refresh() }
    }

    private var filteredIdentities: [CTKIdentity] {
        showAll ? manager.identities : manager.identities.filter(\.isSSHLabelled)
    }

    @ViewBuilder
    private func identityRow(_ identity: CTKIdentity) -> some View {
        HStack(alignment: .top, spacing: Theme.smallPadding) {
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 4) {
                    if identity.protection == .bio {
                        Image(systemName: "person.fill.badge.shield.checkmark")
                            .foregroundStyle(Theme.accent)
                            .accessibilityLabel("Biometric protected")
                    }
                    Text(identity.label).fontWeight(.medium)
                    if !identity.isValid {
                        Text("(expired)")
                            .font(Theme.captionFont)
                            .foregroundStyle(Theme.errorText)
                    }
                }
                Text(displayHash(identity))
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .foregroundStyle(.secondary)
                if !identity.validToRaw.isEmpty {
                    Text("Valid to \(identity.validToRaw)")
                        .font(Theme.captionFont)
                        .foregroundStyle(.secondary)
                }
            }
            Spacer()
            Button(role: .destructive) {
                pendingDelete = identity
            } label: {
                Image(systemName: "trash")
                    .accessibilityLabel("Delete identity")
            }
            .buttonStyle(.borderless)
            .disabled(manager.isBusy)
        }
        .padding(.vertical, 2)
        .contextMenu {
            if let fingerprint = identity.sshFingerprint {
                Button("Copy SSH fingerprint") {
                    let pb = NSPasteboard.general
                    pb.clearContents()
                    pb.setString(fingerprint, forType: .string)
                }
            }
            Button("Copy public key hash") {
                let pb = NSPasteboard.general
                pb.clearContents()
                pb.setString(identity.publicKeyHash, forType: .string)
            }
        }
    }

    private func displayHash(_ identity: CTKIdentity) -> String {
        if let fingerprint = identity.sshFingerprint {
            return fingerprint
        }
        return identity.publicKeyHash
    }
}

// MARK: - Fallback view for older macOS

/// macOS 15-25 fallback. The Package.swift compile floor is `.v15`,
/// so the file must still link on those versions; the actual SE-SSH
/// surface is `@available(macOS 26.0, *)` and only the fallback shows.
public struct SSHIdentitiesUnavailableView: View {
    public init() {}
    public var body: some View {
        VStack(spacing: Theme.mediumPadding) {
            Image(systemName: "lock.shield")
                .font(.system(size: 32))
                .foregroundStyle(.secondary)
            Text("Secure-Enclave SSH identities require macOS 26 (Tahoe) or later.")
                .multilineTextAlignment(.center)
                .font(Theme.captionFont)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding(Theme.mediumPadding)
    }
}

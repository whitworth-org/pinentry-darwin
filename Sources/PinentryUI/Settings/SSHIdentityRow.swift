// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// SSHIdentityRow.swift — row views for the SSH tab: one Secure Enclave
// identity and one ssh-agent key. Fingerprints and hashes are public
// identifiers, shown in monospaced selectable text.

import SSHIdentity
import SwiftUI

struct SSHIdentityRow: View {

    let identity: CTKIdentity
    let isBusy: Bool
    let onDelete: () -> Void

    var body: some View {
        HStack(alignment: .top, spacing: Theme.smallPadding) {
            VStack(alignment: .leading, spacing: 3) {
                titleLine
                Text(fingerprint)
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .accessibilityLabel(identity.sshFingerprint == nil
                        ? "Public key hash" : "SSH fingerprint")
                    .accessibilityValue(fingerprint)
                if !identity.validToRaw.isEmpty {
                    Text("\(identity.isValid ? "Valid until" : "Expired") \(identity.validToRaw)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            Spacer(minLength: Theme.smallPadding)
            Button(role: .destructive, action: onDelete) {
                Image(systemName: "trash")
            }
            .buttonStyle(.borderless)
            .help("Delete identity")
            .accessibilityLabel("Delete identity \(identity.label)")
            .accessibilityHint("Asks for confirmation first")
            .disabled(isBusy)
        }
        .padding(.vertical, 2)
        .contextMenu {
            if let sshFingerprint = identity.sshFingerprint {
                Button("Copy SSH fingerprint") { Pasteboard.copy(sshFingerprint) }
            }
            Button("Copy public key hash") { Pasteboard.copy(identity.publicKeyHash) }
            Divider()
            Button("Delete identity…", role: .destructive, action: onDelete)
                .disabled(isBusy)
        }
        .accessibilityAction(named: "Delete identity", onDelete)
    }

    private var fingerprint: String { identity.sshFingerprint ?? identity.publicKeyHash }

    private var titleLine: some View {
        HStack(spacing: Theme.smallPadding) {
            Text(identity.label).fontWeight(.medium)
            if identity.protection == .bio {
                SettingsBadge(
                    title: "Touch ID",
                    systemImage: "touchid",
                    tint: Theme.accent
                )
            }
            if !identity.isValid {
                SettingsBadge(
                    title: "Expired",
                    systemImage: "exclamationmark.circle.fill",
                    tint: Theme.errorText
                )
            }
        }
    }
}

struct SSHAgentKeyRow: View {

    let key: SSHAgentKey

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: Theme.smallPadding) {
                Text(key.comment.isEmpty ? "No comment" : key.comment)
                    .fontWeight(.medium)
                if key.isSecurityKey {
                    SettingsBadge(
                        title: "Security key",
                        systemImage: "lock.shield",
                        tint: Theme.accent
                    )
                }
            }
            Text(key.rawLine)
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
                .lineLimit(1)
                .truncationMode(.middle)
                .accessibilityLabel("Public key, \(key.keyType)")
                .accessibilityValue(key.rawLine)
        }
        .padding(.vertical, 2)
        .contextMenu {
            Button("Copy public key") { Pasteboard.copy(key.rawLine) }
        }
    }
}

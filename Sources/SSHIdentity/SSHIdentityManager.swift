// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// SSHIdentityManager.swift — the SwiftUI-facing controller for the
// SSH Identities Settings tab. Marshals between the underlying clients
// (`SCAuthClient`, `SSHAddClient`) and `@Published` UI state.
//
// All UI state lives on the main actor. The clients themselves are
// actors that perform the subprocess I/O off-main.

import Foundation
import os

#if canImport(Combine)
import Combine
#endif

private let log = Logger(
    subsystem: "org.whitworth.pinentry-darwin",
    category: "ssh.manager"
)

// MARK: - Manager

@MainActor
public final class SSHIdentityManager: ObservableObject {

    // MARK: - Published state

    @Published public private(set) var identities: [CTKIdentity] = []
    @Published public private(set) var agentKeys: [SSHAgentKey] = []
    @Published public private(set) var lastError: String?
    @Published public private(set) var isBusy: Bool = false

    /// Non-fatal warning when the last refresh returned a best-effort
    /// (truncated) identity list — e.g. sc_auth's hex and ssh passes
    /// disagreed on row count, so some SSH fingerprints are missing.
    /// Distinct from `lastError`: the list is still usable.
    @Published public private(set) var lastWarning: String?

    // MARK: - Dependencies

    private let scAuth: any SCAuthClientProtocol
    private let sshAdd: any SSHAddClientProtocol

    public init(
        scAuth: any SCAuthClientProtocol = SCAuthClient(),
        sshAdd: any SSHAddClientProtocol = SSHAddClient()
    ) {
        self.scAuth = scAuth
        self.sshAdd = sshAdd
    }

    // MARK: - Public surface

    /// Refresh both lists from the system. Errors are surfaced via
    /// `lastError` rather than thrown — the UI consumes them through
    /// the published binding.
    public func refresh() async {
        lastWarning = nil
        await runGuarded { [scAuth, sshAdd] in
            async let ctk = scAuth.listIdentities()
            async let agent = sshAdd.listAgentIdentities()
            return try await (ctk, agent)
        } onSuccess: { [weak self] result in
            self?.identities = result.0.identities
            self?.agentKeys = result.1
            self?.lastWarning = result.0.partial.map(Self.describePartial)
        }
    }

    /// Create a new SE-backed identity with the given label. The
    /// system surfaces a Touch ID sheet during the underlying
    /// `sc_auth create-ctk-identity` call.
    public func create(label: String) async {
        await runGuarded { [scAuth] in
            try await scAuth.createIdentity(label: label)
        } onSuccess: { _ in /* refresh follows */ }
        await refresh()
    }

    public func delete(_ identity: CTKIdentity) async {
        await runGuarded { [scAuth] in
            try await scAuth.deleteIdentity(publicKeyHash: identity.publicKeyHash)
        } onSuccess: { _ in /* refresh follows */ }
        await refresh()
    }

    /// Register all SE-resident identities with the running ssh-agent.
    /// On success, refreshes the agent list so the UI reflects the new
    /// `sk-ecdsa-sha2-nistp256@openssh.com` entries.
    public func registerWithAgent() async {
        await runGuarded { [sshAdd] in
            try await sshAdd.registerSecurityKeyProvider()
            return try await sshAdd.listAgentIdentities()
        } onSuccess: { [weak self] keys in
            self?.agentKeys = keys
        }
    }

    public func dismissError() {
        lastError = nil
    }

    public func dismissWarning() {
        lastWarning = nil
    }

    private static func describePartial(
        _ reason: CTKIdentityListing.PartialReason
    ) -> String {
        switch reason {
        case let .fingerprintCountMismatch(hexRows, sshRows):
            return "Showing \(hexRows) identities, but sc_auth reported "
                + "\(sshRows) SSH fingerprint rows — some fingerprints "
                + "could not be paired and are not shown."
        }
    }

    // MARK: - Internal helpers

    private func runGuarded<T: Sendable>(
        _ work: @Sendable () async throws -> T,
        onSuccess: @MainActor (T) -> Void
    ) async {
        isBusy = true
        lastError = nil
        defer { isBusy = false }
        do {
            let value = try await work()
            onSuccess(value)
        } catch {
            let message = formatError(error)
            log.error("ssh manager error: \(message, privacy: .private)")
            lastError = message
        }
    }

    private func formatError(_ error: Error) -> String {
        switch error {
        case let SCAuthError.commandFailed(code, stderr):
            return "sc_auth exit \(code): \(stderr.trimmingCharacters(in: .whitespacesAndNewlines))"
        case let SCAuthError.invalidLabel(label):
            return "Invalid label '\(label)'. Allowed: A-Z, a-z, 0-9, dot, underscore, hyphen, 1-64 chars."
        case let SCAuthError.invalidHash(hash):
            return "Invalid public key hash '\(hash)'."
        case let SCAuthError.binaryMissing(path):
            return "sc_auth binary missing at \(path)."
        case let SCAuthError.parseError(parseErr):
            return "Could not parse sc_auth output: \(parseErr)"
        case let SSHAddError.commandFailed(code, stderr):
            return "ssh-add exit \(code): \(stderr.trimmingCharacters(in: .whitespacesAndNewlines))"
        case let SSHAddError.binaryMissing(path):
            return "ssh-add binary missing at \(path)."
        case let SSHAddError.providerMissing(path):
            return "ssh-keychain provider missing at \(path)."
        default:
            return String(describing: error)
        }
    }
}

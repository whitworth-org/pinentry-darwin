// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// SSHAddClient.swift — `actor` wrapper around `/usr/bin/ssh-add` for
// the two operations the SSH Identities UI needs:
//   * `ssh-add -K -S /usr/lib/ssh-keychain.dylib` — register all
//     resident SE-backed identities with the running ssh-agent.
//   * `ssh-add -L` — list public keys currently held by ssh-agent.
//
// The provider path is pinned to the system-installed dylib;
// callers cannot redirect it.

import Foundation
import os

private let log = Logger(
    subsystem: "org.whitworth.pinentry-darwin",
    category: "ssh.add"
)

// MARK: - Protocol

public protocol SSHAddClientProtocol: Sendable {
    func registerSecurityKeyProvider() async throws -> [String]
    func listAgentIdentities() async throws -> [SSHAgentKey]
}

// MARK: - Errors

public enum SSHAddError: Error, Equatable, Sendable {
    case binaryMissing(path: String)
    case providerMissing(path: String)
    case commandFailed(exitCode: Int32, stderr: String)
}

// MARK: - SSHAddClient

public actor SSHAddClient: SSHAddClientProtocol {
    public static let binaryPath = "/usr/bin/ssh-add"
    public static let providerPath = "/usr/lib/ssh-keychain.dylib"

    private let binary: String
    private let provider: String
    private let runner: any ProcessRunner

    public init(
        binary: String = SSHAddClient.binaryPath,
        provider: String = SSHAddClient.providerPath,
        runner: any ProcessRunner = RealProcessRunner()
    ) {
        self.binary = binary
        self.provider = provider
        self.runner = runner
    }

    // MARK: - registerSecurityKeyProvider

    /// `ssh-add -K -S <provider>` — register all SE-resident identities
    /// with the running ssh-agent. Returns the SSH fingerprints
    /// reported as added.
    public func registerSecurityKeyProvider() async throws -> [String] {
        let result = try await runner.run(
            executable: binary,
            arguments: ["-K", "-S", provider],
            stdin: nil
        )
        guard result.didSucceed else {
            log.error("ssh-add -K exit=\(result.exitCode, privacy: .public) stderr=\(result.stderr, privacy: .public)")
            throw SSHAddError.commandFailed(
                exitCode: result.exitCode,
                stderr: result.stderr
            )
        }
        return parseSSHAddRegistration(result.stdout + "\n" + result.stderr)
    }

    // MARK: - listAgentIdentities

    /// `ssh-add -L` — list public keys in the running ssh-agent.
    /// Exit 1 with "The agent has no identities." stdout is normal
    /// for an empty agent; we treat it as an empty list, not an error.
    public func listAgentIdentities() async throws -> [SSHAgentKey] {
        let result = try await runner.run(
            executable: binary,
            arguments: ["-L"],
            stdin: nil
        )
        // ssh-add -L exits 1 when the agent is empty. Detect that
        // common case and return empty rather than throwing.
        let combined = result.stdout + "\n" + result.stderr
        if combined.lowercased().contains("the agent has no identities") {
            return []
        }
        guard result.didSucceed else {
            log.error("ssh-add -L exit=\(result.exitCode, privacy: .public) stderr=\(result.stderr, privacy: .public)")
            throw SSHAddError.commandFailed(
                exitCode: result.exitCode,
                stderr: result.stderr
            )
        }
        return parseSSHAddList(result.stdout)
    }
}

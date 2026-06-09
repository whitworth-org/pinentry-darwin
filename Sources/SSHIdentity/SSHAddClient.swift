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
    func registerSecurityKeyProvider() async throws
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

    /// `-K` may touch the SE provider; `-L` just queries the agent over
    /// a unix socket. Both should fail fast if the agent is wedged — a
    /// dead `SSH_AUTH_SOCK` must not hang the Settings tab.
    static let registerTimeout: Duration = .seconds(30)
    static let listTimeout: Duration = .seconds(15)

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
    /// with the running ssh-agent. Throws on non-zero exit; the caller
    /// re-lists the agent to observe the resulting state.
    public func registerSecurityKeyProvider() async throws {
        let result = try await runner.run(
            executable: binary,
            arguments: ["-K", "-S", provider],
            stdin: nil,
            timeout: Self.registerTimeout
        )
        guard result.didSucceed else {
            log.error("ssh-add -K exit=\(result.exitCode, privacy: .public) stderr=\(result.stderr, privacy: .private)")
            throw SSHAddError.commandFailed(
                exitCode: result.exitCode,
                stderr: result.stderr
            )
        }
    }

    // MARK: - listAgentIdentities

    /// `ssh-add -L` — list public keys in the running ssh-agent.
    /// An empty agent exits 1 and prints "The agent has no identities."
    /// to stdout; we treat that as an empty list, not an error.
    public func listAgentIdentities() async throws -> [SSHAgentKey] {
        let result = try await runner.run(
            executable: binary,
            arguments: ["-L"],
            stdin: nil,
            timeout: Self.listTimeout
        )
        // Empty-agent detection. ssh-add(1) exits 1 here, so anchor on
        // exit==1 AND the sentinel as a standalone stdout line — never a
        // substring scan over stdout+stderr, which a public-key comment
        // containing the phrase (or a non-English locale) could trip.
        if result.exitCode == 1, isEmptyAgentMessage(result.stdout) {
            return []
        }
        guard result.didSucceed else {
            log.error("ssh-add -L exit=\(result.exitCode, privacy: .public) stderr=\(result.stderr, privacy: .private)")
            throw SSHAddError.commandFailed(
                exitCode: result.exitCode,
                stderr: result.stderr
            )
        }
        return parseSSHAddList(result.stdout)
    }
}

/// True when `stdout` is the ssh-agent "no identities" sentinel: a
/// single non-blank line equal to the documented message (case- and
/// trailing-punctuation-tolerant). Anchored to a whole line so a key
/// comment that merely contains the phrase cannot be mistaken for it.
func isEmptyAgentMessage(_ stdout: String) -> Bool {
    let lines = stdout
        .split(separator: "\n", omittingEmptySubsequences: true)
        .map { $0.trimmingCharacters(in: .whitespaces) }
        .filter { !$0.isEmpty }
    guard lines.count == 1, let line = lines.first else { return false }
    let normalised = line.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
    return normalised == "the agent has no identities"
}

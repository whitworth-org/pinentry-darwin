// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// SCAuthClient.swift — `actor` wrapper around `/usr/sbin/sc_auth`.
// All subprocess invocations use explicit argv arrays so user-supplied
// labels can never be interpreted as shell metacharacters. Labels are
// pre-validated against a tight allow-list before they reach here.
//
// On macOS 26 the `create-ctk-identity` subcommand is what triggers the
// Touch ID sheet; the system owns that UI, not our process. We just
// wait for the subprocess to exit and surface any non-zero status as a
// typed error.

import Foundation
import os

private let log = Logger(
    subsystem: "org.whitworth.pinentry-darwin",
    category: "ssh.scauth"
)

// MARK: - Protocol (for tests)

public protocol SCAuthClientProtocol: Sendable {
    func listIdentities() async throws -> [CTKIdentity]
    func createIdentity(label: String) async throws
    func deleteIdentity(publicKeyHash: String) async throws
}

// MARK: - Errors

public enum SCAuthError: Error, Equatable, Sendable {
    case binaryMissing(path: String)
    case invalidLabel(String)
    case invalidHash(String)
    case commandFailed(exitCode: Int32, stderr: String)
    case parseError(SSHIdentityParseError)
}

// MARK: - Label / hash validation

/// Allowed label characters: ASCII letters, digits, dot, underscore,
/// hyphen. Total length 1..=64. Conservative on purpose — `sc_auth -l`
/// passes the label through into a CryptoTokenKit identity, and the
/// system may have its own normalisation rules; we want a value that
/// round-trips cleanly through `list-ctk-identities`.
public func validateLabel(_ label: String) -> Bool {
    let bytes = Array(label.utf8)
    guard (1...64).contains(bytes.count) else { return false }
    for b in bytes {
        let isUpper = (0x41...0x5A).contains(b)  // A-Z
        let isLower = (0x61...0x7A).contains(b)  // a-z
        let isDigit = (0x30...0x39).contains(b)  // 0-9
        let isPunct = b == 0x2E || b == 0x5F || b == 0x2D  // . _ -
        if !(isUpper || isLower || isDigit || isPunct) { return false }
    }
    return true
}

/// Allowed hash format: exactly 40 hex characters (SHA-1) as printed
/// by `sc_auth list-ctk-identities` without `-t ssh`.
public func validatePublicKeyHash(_ hash: String) -> Bool {
    let bytes = Array(hash.utf8)
    guard bytes.count == 40 else { return false }
    for b in bytes {
        let isDigit = (0x30...0x39).contains(b)
        let isUpperHex = (0x41...0x46).contains(b)  // A-F
        let isLowerHex = (0x61...0x66).contains(b)  // a-f
        if !(isDigit || isUpperHex || isLowerHex) { return false }
    }
    return true
}

// MARK: - SCAuthClient

public actor SCAuthClient: SCAuthClientProtocol {
    public static let binaryPath = "/usr/sbin/sc_auth"

    private let binary: String
    private let runner: any ProcessRunner

    public init(
        binary: String = SCAuthClient.binaryPath,
        runner: any ProcessRunner = RealProcessRunner()
    ) {
        self.binary = binary
        self.runner = runner
    }

    // MARK: - listIdentities

    /// Run `sc_auth list-ctk-identities` twice: once for the hex hash
    /// (used by `delete-ctk-identity -h`) and once with `-t ssh` for
    /// the SSH fingerprint. We merge the two outputs by row order
    /// since `sc_auth` lists identities in a stable order within a
    /// single process invocation.
    public func listIdentities() async throws -> [CTKIdentity] {
        let hexResult = try await runner.run(
            executable: binary,
            arguments: ["list-ctk-identities"],
            stdin: nil
        )
        try requireSuccess(hexResult)

        let sshResult = try await runner.run(
            executable: binary,
            arguments: ["list-ctk-identities", "-t", "ssh"],
            stdin: nil
        )
        try requireSuccess(sshResult)

        let hexRows: [CTKIdentity]
        let sshRows: [CTKIdentity]
        do {
            hexRows = try parseSCAuthList(
                hexResult.stdout,
                interpretingHashAsSSHFingerprint: false
            )
            sshRows = try parseSCAuthList(
                sshResult.stdout,
                interpretingHashAsSSHFingerprint: true
            )
        } catch let err as SSHIdentityParseError {
            throw SCAuthError.parseError(err)
        }

        // Merge: zip by index when counts match, else fall back to
        // hex-only rows (the SSH variant is enrichment, not source of
        // truth).
        guard hexRows.count == sshRows.count else {
            log.warning("sc_auth row count mismatch: hex=\(hexRows.count, privacy: .public) ssh=\(sshRows.count, privacy: .public)")
            return hexRows
        }
        return zip(hexRows, sshRows).map { hex, ssh in
            CTKIdentity(
                keyType: hex.keyType,
                publicKeyHash: hex.publicKeyHash,
                sshFingerprint: ssh.sshFingerprint,
                protection: hex.protection,
                label: hex.label,
                commonName: hex.commonName,
                emailAddress: hex.emailAddress,
                validToRaw: hex.validToRaw,
                isValid: hex.isValid
            )
        }
    }

    // MARK: - createIdentity

    /// Run `sc_auth create-ctk-identity -l <label> -k p-256-ne -t bio`.
    /// Surfaces a Touch ID sheet owned by the OS; this call returns
    /// once the user authorises (or denies) the operation.
    public func createIdentity(label: String) async throws {
        guard validateLabel(label) else {
            throw SCAuthError.invalidLabel(label)
        }
        let result = try await runner.run(
            executable: binary,
            arguments: [
                "create-ctk-identity",
                "-l", label,
                "-k", "p-256-ne",
                "-t", "bio",
            ],
            stdin: nil
        )
        try requireSuccess(result)
    }

    // MARK: - deleteIdentity

    public func deleteIdentity(publicKeyHash: String) async throws {
        guard validatePublicKeyHash(publicKeyHash) else {
            throw SCAuthError.invalidHash(publicKeyHash)
        }
        let result = try await runner.run(
            executable: binary,
            arguments: ["delete-ctk-identity", "-h", publicKeyHash],
            stdin: nil
        )
        try requireSuccess(result)
    }

    // MARK: - Helpers

    private func requireSuccess(_ result: ProcessResult) throws {
        guard result.didSucceed else {
            log.error("sc_auth exit=\(result.exitCode, privacy: .public) stderr=\(result.stderr, privacy: .public)")
            throw SCAuthError.commandFailed(
                exitCode: result.exitCode,
                stderr: result.stderr
            )
        }
    }
}

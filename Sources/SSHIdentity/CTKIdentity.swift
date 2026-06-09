// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// CTKIdentity.swift — value types describing the Secure-Enclave-backed
// CryptoTokenKit identities exposed by `/usr/sbin/sc_auth` and
// `/usr/lib/ssh-keychain.dylib` on macOS 26 (Tahoe).
//
// SE-resident keys never enter this process. We only ever hold the
// public material the system already exposes via the CLI: the hex/SHA256
// public-key hash, the optional SSH fingerprint, the user-chosen label,
// and the validity window. There is no SecureBytes here.

import Foundation

// MARK: - Key type

/// The `sc_auth -k` keytype value. `_ne` variants are non-exportable
/// (generated on the SE); the bare variants are exportable (key wrapped
/// by the SE but key material can be exported via `sc_auth
/// export-ctk-identity`).
public enum CTKKeyType: String, Sendable, CaseIterable {
    case p256NE = "p-256-ne"
    case p384NE = "p-384-ne"
    case p521NE = "p-521-ne"  // sc_auth accepts only -ne for p-521
    case p256 = "p-256"
    case p384 = "p-384"
    case p521 = "p-521"
}

// MARK: - Protection

/// The `sc_auth -t` protection value. `bio` requires Touch ID / Optic ID
/// per use; `none` requires no biometric (still SE-resident).
public enum CTKProtection: String, Sendable {
    case bio
    case none
    case unknown
}

// MARK: - CTKIdentity

/// One row from `sc_auth list-ctk-identities`.
///
/// `publicKeyHash` is the hex SHA-1 hash used by `sc_auth
/// delete-ctk-identity -h <hash>`. `sshFingerprint`, when present, is
/// the `SHA256:<base64>` value emitted by `sc_auth list-ctk-identities
/// -t ssh` — the same fingerprint OpenSSH prints in `ssh-add -l`.
///
/// `validTo` is the raw string from sc_auth (locale-formatted by the
/// CLI, e.g. `23.11.26, 17:09`). We surface it verbatim rather than
/// risk a misparse; the UI shows the string as-is. `isValid` mirrors
/// the trailing `YES`/`NO` column.
public struct CTKIdentity: Sendable, Hashable, Identifiable {
    public let keyType: CTKKeyType?
    public let publicKeyHash: String
    public let sshFingerprint: String?
    public let protection: CTKProtection
    public let label: String
    public let commonName: String
    public let emailAddress: String
    public let validToRaw: String
    public let isValid: Bool

    public var id: String { publicKeyHash }

    public init(
        keyType: CTKKeyType?,
        publicKeyHash: String,
        sshFingerprint: String?,
        protection: CTKProtection,
        label: String,
        commonName: String,
        emailAddress: String,
        validToRaw: String,
        isValid: Bool
    ) {
        self.keyType = keyType
        self.publicKeyHash = publicKeyHash
        self.sshFingerprint = sshFingerprint
        self.protection = protection
        self.label = label
        self.commonName = commonName
        self.emailAddress = emailAddress
        self.validToRaw = validToRaw
        self.isValid = isValid
    }

    /// True when the row was created via `sc_auth create-ctk-identity
    /// -l ssh*`. The UI defaults to filtering by this flag so FileVault
    /// recovery identities are not surfaced alongside user SSH keys.
    public var isSSHLabelled: Bool {
        label.lowercased().hasPrefix("ssh")
    }
}

// MARK: - Identity listing

/// Result of `SCAuthClient.listIdentities`. Carries the merged rows plus
/// a non-fatal `partial` signal: when the hex-hash and `-t ssh` passes
/// disagree on row count, we still return the best-effort hex rows (SSH
/// fingerprints are enrichment, not source of truth) but flag that some
/// SSH fingerprints could not be paired, so the UI can say so rather
/// than silently showing identities with missing fingerprints.
public struct CTKIdentityListing: Sendable, Equatable {
    public let identities: [CTKIdentity]
    public let partial: PartialReason?

    public enum PartialReason: Sendable, Equatable {
        /// hex-pass and ssh-pass row counts disagreed.
        case fingerprintCountMismatch(hexRows: Int, sshRows: Int)
    }

    public init(identities: [CTKIdentity], partial: PartialReason? = nil) {
        self.identities = identities
        self.partial = partial
    }
}

// MARK: - Agent key

/// One line from `ssh-add -L`. We split the OpenSSH wire format
/// (`<type> <base64-blob> [comment]`) so the UI can show a fingerprint
/// alongside the comment. The raw line is preserved for clipboard copy.
public struct SSHAgentKey: Sendable, Hashable, Identifiable {
    public let keyType: String
    public let base64Blob: String
    public let comment: String
    public let rawLine: String

    public var id: String { base64Blob }

    public init(
        keyType: String,
        base64Blob: String,
        comment: String,
        rawLine: String
    ) {
        self.keyType = keyType
        self.base64Blob = base64Blob
        self.comment = comment
        self.rawLine = rawLine
    }

    /// True for `sk-ecdsa-sha2-nistp256@openssh.com` and friends — the
    /// FIDO-style key types the SE-SSH provider produces.
    public var isSecurityKey: Bool {
        keyType.hasPrefix("sk-")
    }
}

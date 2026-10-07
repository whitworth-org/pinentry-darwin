// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// SavedPassphrases.swift — shared behaviour for the Forget and Forget-all
// actions: bulk deletion that reports partial failure, and plain-language
// descriptions of Keychain errors.

public import Foundation
import KeychainStore
import Security

/// Thrown by `SavedPassphrases.forgetAll` when some entries could not be removed.
public struct ForgetAllError: Error, Equatable, LocalizedError {
    public let failed: Int
    public let total: Int
    /// Reason reported for the first failure.
    public let firstReason: String

    public init(failed: Int, total: Int, firstReason: String) {
        self.failed = failed
        self.total = total
        self.firstReason = firstReason
    }

    public var errorDescription: String? {
        "Removed \(total - failed) of \(total) saved passphrases. \(firstReason)"
    }
}

public enum SavedPassphrases {

    /// Delete every entry in `fingerprints`, then drop its per-key override.
    ///
    /// Every entry is attempted. An override is removed only when that entry's
    /// delete succeeded, so a failed delete never loses its policy.
    ///
    /// - Throws: `ForgetAllError` when at least one delete failed.
    public static func forgetAll(
        fingerprints: [String],
        clear: (String) throws -> Void,
        removeOverride: (String) -> Void
    ) throws {
        var failed = 0
        var firstReason: String?
        for fingerprint in fingerprints {
            do {
                try clear(fingerprint)
                removeOverride(fingerprint)
            } catch {
                failed += 1
                firstReason = firstReason ?? failureReason(for: error)
            }
        }
        if let firstReason {
            throw ForgetAllError(
                failed: failed,
                total: fingerprints.count,
                firstReason: firstReason
            )
        }
    }

    /// A short sentence describing why a Keychain operation failed.
    public static func failureReason(for error: any Error) -> String {
        if let error = error as? ForgetAllError {
            return error.errorDescription ?? "Keychain error."
        }
        if let error = error as? KeychainStoreError {
            return describe(error)
        }
        if error is CancellationError {
            return "The operation was cancelled."
        }
        return error.localizedDescription
    }

    private static func describe(_ error: KeychainStoreError) -> String {
        switch error {
        case .userCanceled:
            return "Authentication was cancelled."
        case .degradedNoEntitlement:
            return "This build cannot use the data-protection Keychain."
        case .accessControlFailed:
            return "The Keychain access policy could not be applied."
        case .unexpectedStatus(let status):
            return SecCopyErrorMessageString(status, nil) as String? ?? "Keychain error \(status)."
        }
    }
}

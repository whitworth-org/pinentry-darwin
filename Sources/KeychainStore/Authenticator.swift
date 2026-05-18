// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// Authenticator.swift — LocalAuthentication wiring.
//
// Why this exists: prior to Tier 2, the `.userPresence` ACL on a
// data-protection keychain entry caused macOS to surface its own Touch ID
// sheet, but the sheet's `localizedReason` was the system default — a
// generic "<App> is trying to use Touch ID" string. The user has no way
// to confirm that the prompt is for THEIR GPG key vs. an arbitrary
// background lookup. That's an anti-phishing weakness.
//
// `Authenticator` constructs an `LAContext` with a `localizedReason`
// derived from the `SETDESC` Assuan command — typically something like
// "Please enter the passphrase to unlock the OpenPGP key 0xABCD…". The
// context is then handed to `SecItemCopyMatching` via
// `kSecUseAuthenticationContext`, which causes the same Touch ID sheet
// to display our reason instead of the system default.
//
// Reuse contract (Tier 3): a single `LAContext` instance survives ONE
// successful authentication and may be reused for follow-up Secure-Enclave
// ECDH operations within a short window. AssuanLoop creates one context
// per GETPIN and passes it to both `KeychainStore.lookup` and the future
// `SecureEnclaveWrap.unwrap` call so the user sees one prompt, not two.

import Foundation
import LocalAuthentication
import os

private let log = Logger(
    subsystem: "org.whitworth.pinentry-darwin",
    category: "authenticator"
)

// MARK: - Authenticator

public struct Authenticator: Sendable {

    /// Maximum bytes for the localized reason string. AppKit's sheet
    /// truncates long strings anyway; we cap pre-display so the reason
    /// renders predictably and we don't ship 4 KB of user-controlled
    /// text into a system UI element.
    public static let maxReasonBytes = 256

    /// Sanitize a SETDESC-derived description into a value safe to use as
    /// `LAContext.localizedReason`. Rules:
    ///   - drop C0 control bytes (< 0x20) and DEL (0x7F)
    ///   - collapse runs of whitespace to a single space
    ///   - trim leading/trailing whitespace
    ///   - byte-cap at `maxReasonBytes` (graceful unicode-scalar boundary)
    public static func sanitize(_ description: String?) -> String? {
        guard let raw = description, !raw.isEmpty else { return nil }

        // First pass: strip control bytes, normalise whitespace.
        var out = String.UnicodeScalarView()
        var prevWasSpace = false
        for scalar in raw.unicodeScalars {
            let v = scalar.value
            if v < 0x20 || v == 0x7F {
                if !prevWasSpace {
                    out.append(" ")
                    prevWasSpace = true
                }
                continue
            }
            if scalar == " " {
                if prevWasSpace { continue }
                prevWasSpace = true
            } else {
                prevWasSpace = false
            }
            out.append(scalar)
        }
        let normalised = String(out)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalised.isEmpty else { return nil }

        // Second pass: byte-cap on scalar boundary.
        if normalised.utf8.count <= maxReasonBytes { return normalised }
        var capped = String.UnicodeScalarView()
        var used = 0
        for scalar in normalised.unicodeScalars {
            let n = String(scalar).utf8.count
            if used + n > maxReasonBytes { break }
            capped.append(scalar)
            used += n
        }
        return String(capped)
    }

    /// Build an `LAContext` configured for a single use of `.userPresence`
    /// / `.biometry*` -gated keychain unlock or Secure Enclave ECDH.
    ///
    /// `reason` is the sanitized description from `Authenticator.sanitize`.
    /// Pass nil to use the system default reason (matches pre-Tier-2
    /// behaviour). The context's `interactionNotAllowed` is left false
    /// so the system can surface the sheet.
    @MainActor
    public static func makeContext(reason: String?) -> LAContext {
        let context = LAContext()
        if let reason, !reason.isEmpty {
            context.localizedReason = reason
        }
        // Reuse window: a successful authentication remains valid for
        // 10 seconds across multiple Sec* calls that pass the same
        // context. Long enough to cover a keychain lookup followed by a
        // Secure Enclave ECDH within the same GETPIN; short enough that
        // an idle context cannot silently authorise a later operation.
        context.touchIDAuthenticationAllowableReuseDuration = 10
        // Default behaviour: surface the sheet on demand. We do NOT set
        // interactionNotAllowed = true here; the legacy migration probe
        // sets `kSecUseAuthenticationUISkip` at the query level instead,
        // which is the per-query knob.
        return context
    }

    /// Best-effort diagnostic. Logs whether the current device has a
    /// usable biometric and which one. No PII; helpful when the lookup
    /// path silently degrades because the user disabled Touch ID.
    @MainActor
    public static func logCapabilityOnce() {
        capabilityLogFlag.withLock { state in
            guard !state else { return }
            state = true
            let context = LAContext()
            var error: NSError?
            let canBiometry = context.canEvaluatePolicy(
                .deviceOwnerAuthenticationWithBiometrics,
                error: &error
            )
            let canPasscode = context.canEvaluatePolicy(
                .deviceOwnerAuthentication,
                error: nil
            )
            let biotype: String
            switch context.biometryType {
            case .touchID:    biotype = "touchID"
            case .opticID:    biotype = "opticID"
            case .faceID:     biotype = "faceID"
            case .none:       biotype = "none"
            @unknown default: biotype = "unknown"
            }
            log.info("biometry=\(biotype, privacy: .public) canBiometry=\(canBiometry, privacy: .public) canPasscode=\(canPasscode, privacy: .public)")
        }
    }
}

/// One-shot guard so the capability log fires once per process.
private let capabilityLogFlag = OSAllocatedUnfairLock<Bool>(initialState: false)

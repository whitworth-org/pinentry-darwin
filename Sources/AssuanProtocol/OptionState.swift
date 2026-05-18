// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// OptionState.swift — accumulator for `OPTION key[=value]` settings sent by
// gpg-agent before a GETPIN/CONFIRM/MESSAGE. The mapping mirrors upstream
// `option_handler` in /Users/rwhitworth/Development/pinentry/pinentry/pinentry.c
// lines 1029–1261.
//
// Unknown keys are silently ignored; that's the correct upstream behaviour
// for forward-compat (gpg-agent may set new options we don't model yet).

import Foundation
import Darwin

// MARK: - OptionState

public struct OptionState: Sendable, Equatable {
    public var grab: Bool = false
    public var ttyName: String?
    public var ttyType: String?
    public var lcCType: String?
    public var lcMessages: String?
    public var allowExternalPasswordCache: Bool = false
    public var defaultOK: String?
    public var defaultCancel: String?
    public var defaultPrompt: String?
    public var defaultPwManager: String?
    public var defaultCfVisi: String?
    public var defaultTtVisi: String?
    public var defaultTtHide: String?
    public var defaultCapsHint: String?
    public var ownerPID: pid_t?
    public var ownerUID: uid_t?
    public var ownerHost: String?
    public var parentWindowID: Int?
    public var invisibleChar: String?
    public var formattedPassphrase: Bool = false
    public var formattedPassphraseHint: String?
    public var constraintsEnforce: Bool = false
    public var constraintsHintShort: String?
    public var constraintsHintLong: String?
    public var constraintsErrorTitle: String?
    public var allowEmacsPrompt: Bool = false
    public var touchFile: String?
    public var displayName: String?

    /// `--no-symkey-cache` (Assuan OPTION). Set when gpg-agent tells us
    /// not to cache the passphrase for symmetric-encryption operations.
    /// The pinentry binary cannot tell symmetric from asymmetric flows
    /// without a SETKEYINFO mode hint, so when this is set we
    /// conservatively suppress caching entirely for the session.
    public var noSymkeyCache: Bool = false

    public init() {}

    /// Reset per-operation OPTION flags. RESET in the Assuan protocol
    /// clears per-operation state but preserves session-level negotiation
    /// (ttyname, lc-ctype, default-* labels, etc.). `no-symkey-cache` is
    /// a per-operation hint from gpg-agent: a symmetric op may set it,
    /// the next operation (potentially asymmetric) should start fresh
    /// rather than inheriting the suppression. Upstream gpg-agent
    /// re-issues the OPTION on every askpin when --no-symkey-cache is
    /// in effect, so clearing here does not break that flow.
    public mutating func resetPerOperation() {
        noSymkeyCache = false
    }

    /// AS-9: per-OPTION-value cap. Each option text field is bounded
    /// to 1024 bytes to prevent a hostile peer from steadily inflating
    /// session-lifetime memory by re-issuing OPTION with ever-longer
    /// payloads. Single-line max is already 1000 bytes (LineCodec
    /// enforces); this is belt-and-braces against any path that
    /// concatenates or accumulates without re-bounding.
    private static let maxOptionValueBytes = 1024

    @inline(__always)
    private static func cap(_ value: String?) -> String? {
        guard let value else { return nil }
        if value.utf8.count <= maxOptionValueBytes { return value }
        // String.prefix counts in characters but we want a byte cap;
        // walk the UTF-8 view explicitly. Cheap and bounded.
        var out = String.UnicodeScalarView()
        var bytesUsed = 0
        for scalar in value.unicodeScalars {
            let scalarBytes = String(scalar).utf8.count
            if bytesUsed + scalarBytes > maxOptionValueBytes { break }
            out.append(scalar)
            bytesUsed += scalarBytes
        }
        return String(out)
    }

    // MARK: Apply

    /// Apply one parsed `OPTION key[=value]` pair. `value` is `nil` for
    /// flag-style options (e.g. `OPTION grab` / `OPTION no-grab`).
    public mutating func apply(key: String, value: String?) {
        // AS-9: cap any caller-supplied value at the apply boundary.
        // Flag-style options (value == nil) flow through unchanged.
        let value = Self.cap(value)
        switch key {
        case "grab":
            grab = true
        case "no-grab":
            grab = false

        case "ttyname":
            ttyName = value
        case "ttytype":
            ttyType = value
        case "lc-ctype":
            lcCType = value
        case "lc-messages":
            lcMessages = value

        case "allow-external-password-cache":
            allowExternalPasswordCache = true
        case "allow-emacs-prompt":
            allowEmacsPrompt = true

        // Button/prompt-style labels carry GTK mnemonic markers ("_OK") in
        // gpg-agent's wire shipments. Strip at ingestion so downstream
        // consumers see clean text. Sentence-form options (cf-visi /
        // capshint) are left untouched — they're message text, not labels.
        case "default-ok":
            defaultOK = Mnemonic.stripOptional(value)
        case "default-cancel":
            defaultCancel = Mnemonic.stripOptional(value)
        case "default-prompt":
            defaultPrompt = Mnemonic.stripOptional(value)
        case "default-pwmngr":
            defaultPwManager = Mnemonic.stripOptional(value)
        case "default-cf-visi":
            defaultCfVisi = value
        case "default-tt-visi":
            defaultTtVisi = value
        case "default-tt-hide":
            defaultTtHide = value
        case "default-capshint":
            defaultCapsHint = value

        case "owner":
            applyOwner(value)

        case "parent-wid":
            if let v = value, let n = Int(v) {
                parentWindowID = n
            }

        case "touch-file":
            touchFile = value

        case "invisible-char":
            invisibleChar = value

        case "formatted-passphrase":
            formattedPassphrase = true
        case "formatted-passphrase-hint":
            formattedPassphraseHint = value

        case "constraints-enforce":
            constraintsEnforce = true
        case "constraints-hint-short":
            constraintsHintShort = value
        case "constraints-hint-long":
            constraintsHintLong = value
        case "constraints-error-title":
            constraintsErrorTitle = value

        case "display":
            displayName = value

        case "no-symkey-cache":
            noSymkeyCache = true

        default:
            // Silently ignore unknown options; matches upstream's tolerance
            // for forward-compat. We never throw here.
            break
        }
    }

    // MARK: Owner parsing

    /// Parse an `owner` value of the form `PID[/UID][ HOST]`. Mirrors the
    /// upstream parser at pinentry.c:1094–1133.
    private mutating func applyOwner(_ value: String?) {
        ownerPID = nil
        ownerUID = nil
        ownerHost = nil
        guard let value, !value.isEmpty else { return }

        // Split off optional " HOST" tail first.
        var head = value
        var host: String?
        if let spaceIdx = value.firstIndex(of: " ") {
            head = String(value[..<spaceIdx])
            let tail = value[value.index(after: spaceIdx)...]
                .trimmingCharacters(in: .whitespaces)
            if !tail.isEmpty { host = tail }
        }

        // head is now "PID" or "PID/UID".
        let parts = head.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
        // AS-7: reject negative or zero PIDs. POSIX guarantees pid_t > 0
        // for real processes; 0 is the "current process group" sentinel
        // and negative values would round-trip as nonsense to any
        // downstream process-management call.
        if let pid = parts.first.flatMap({ Int32($0) }), pid > 0 {
            ownerPID = pid_t(pid)
        }
        if parts.count == 2, let uidVal = UInt32(parts[1]) {
            ownerUID = uid_t(uidVal)
        }
        ownerHost = host
    }
}

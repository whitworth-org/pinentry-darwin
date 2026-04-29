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

    public init() {}

    // MARK: Apply

    /// Apply one parsed `OPTION key[=value]` pair. `value` is `nil` for
    /// flag-style options (e.g. `OPTION grab` / `OPTION no-grab`).
    public mutating func apply(key: String, value: String?) {
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

        case "default-ok":
            defaultOK = value
        case "default-cancel":
            defaultCancel = value
        case "default-prompt":
            defaultPrompt = value
        case "default-pwmngr":
            defaultPwManager = value
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
        if let pid = parts.first.flatMap({ Int32($0) }) {
            ownerPID = pid_t(pid)
        }
        if parts.count == 2, let uidVal = UInt32(parts[1]) {
            ownerUID = uid_t(uidVal)
        }
        ownerHost = host
    }
}

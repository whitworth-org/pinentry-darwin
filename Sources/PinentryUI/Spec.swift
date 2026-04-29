// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// Spec.swift — value types describing what to present and how to report
// the result. The AppDelegate fills a `DialogSpec` from the accumulated
// Assuan state (SETDESC / SETPROMPT / SETTITLE / SETERROR / SETKEYINFO /
// SETREPEAT / SETTIMEOUT / SETQUALITYBAR / OPTION default-*) and hands it
// to the `PinentryCoordinator`.

import Foundation
import SecureMemory

// MARK: - DialogSpec

public struct DialogSpec: Sendable {

    public enum Kind: Sendable {
        case pin
        case confirm(oneButton: Bool)
        case message
    }

    public enum KeyInfo: Sendable {
        /// `mode` is the cache mode character from `SETKEYINFO m/<fpr>`,
        /// commonly `n` (normal) or `s` (ssh). `fingerprint` is the raw
        /// hex string, displayed in the prompt UI as a monospace hint.
        case key(mode: Character, fingerprint: String)
    }

    /// Localised fallback button labels gathered from
    /// `OPTION default-{ok,cancel,prompt,…}`. The UI uses these only when
    /// the corresponding explicit `SET{OK,CANCEL,…}` field is nil.
    public struct DefaultLabels: Sendable {
        public var ok: String = "OK"
        public var cancel: String = "Cancel"
        public var prompt: String = "Passphrase:"
        public init() {}
    }

    public var kind: Kind
    public var title: String?
    public var description: String?
    public var prompt: String?
    public var error: String?

    public var okLabel: String?
    public var notOKLabel: String?
    public var cancelLabel: String?

    public var repeatPrompt: String?
    public var repeatError: String?
    public var repeatOK: String?

    public var qualityBarLabel: String?
    public var qualityBarTooltip: String?

    public var keyInfo: KeyInfo?
    public var allowKeychainSave: Bool

    public var timeoutSeconds: Int?

    public var defaults: DefaultLabels

    public init(
        kind: Kind,
        title: String? = nil,
        description: String? = nil,
        prompt: String? = nil,
        error: String? = nil,
        okLabel: String? = nil,
        notOKLabel: String? = nil,
        cancelLabel: String? = nil,
        repeatPrompt: String? = nil,
        repeatError: String? = nil,
        repeatOK: String? = nil,
        qualityBarLabel: String? = nil,
        qualityBarTooltip: String? = nil,
        keyInfo: KeyInfo? = nil,
        allowKeychainSave: Bool = false,
        timeoutSeconds: Int? = nil,
        defaults: DefaultLabels = DefaultLabels()
    ) {
        self.kind = kind
        self.title = title
        self.description = description
        self.prompt = prompt
        self.error = error
        self.okLabel = okLabel
        self.notOKLabel = notOKLabel
        self.cancelLabel = cancelLabel
        self.repeatPrompt = repeatPrompt
        self.repeatError = repeatError
        self.repeatOK = repeatOK
        self.qualityBarLabel = qualityBarLabel
        self.qualityBarTooltip = qualityBarTooltip
        self.keyInfo = keyInfo
        self.allowKeychainSave = allowKeychainSave
        self.timeoutSeconds = timeoutSeconds
        self.defaults = defaults
    }

    // MARK: - Resolved labels

    /// The OK label preferring the explicit SET value, falling back to
    /// the localised default, falling back to "OK".
    public var resolvedOK: String {
        okLabel ?? defaults.ok
    }

    /// The Cancel label preferring the explicit SET value, falling back to
    /// the localised default, falling back to "Cancel".
    public var resolvedCancel: String {
        cancelLabel ?? defaults.cancel
    }

    /// The prompt label preferring the explicit SET value, falling back to
    /// the localised default, falling back to "Passphrase:". An explicit
    /// SETPROMPT with an empty argument falls through to `defaults.prompt`
    /// rather than rendering a blank label.
    public var resolvedPrompt: String {
        if let p = prompt, !p.isEmpty { return p }
        return defaults.prompt
    }
}

// MARK: - DialogResult

public enum DialogResult: Sendable {
    /// Pin entry confirmed; the caller takes ownership of the SecureBytes.
    case pin(SecureBytes, savedToKeychain: Bool)
    /// CONFIRM accepted (OK button).
    case confirmed
    /// CONFIRM declined via NotOK / negative button.
    case notConfirmed
    /// User pressed Cancel.
    case canceled
    /// User clicked the red close button rather than Cancel.
    case windowClosed
    /// SETTIMEOUT expired before the user resolved the dialog.
    case timedOut
}

// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// AssuanLoop.swift — the protocol-handler that drives one pinentry session.
//
// Lifecycle:
//   1. emit greeting
//   2. read commands until BYE / EOF
//   3. for SETxxx commands, mutate `dialog`
//   4. for GETPIN / CONFIRM / MESSAGE, build a DialogSpec and present via
//      the coordinator; map the DialogResult back to the wire
//   5. for GETINFO / CLEARPASSPHRASE / RESET, respond inline
//
// Confidentiality:
//   - PIN bytes flow through `SecureBytes` end-to-end. We never log them and
//     never reach for `String(data:)` on a `D` payload.
//   - Any thrown error from a Session call is logged as a generic "internal
//     error"; the original `Error` is **not** included in the log message
//     because some session errors carry transcripts that could embed user
//     text. Wire response is a generic ERR.

import Foundation
import os
import AppKit
import AssuanProtocol
import KeychainStore
import PinentryUI
import SecureMemory

// MARK: - Logger

/// Control-flow logger only. Never log secrets or quality scores.
///
/// Privacy convention (per security review L11):
///
/// * Static format strings with no interpolation are inherently safe
///   — the unified-logging redaction model only applies to
///   interpolated values.
/// * Any interpolated value MUST carry an explicit
///   `\(value, privacy: .public)` or `\(value, privacy: .private)`
///   marker. `.public` for non-sensitive control-flow context
///   (errno, exit code, command verb), `.private` for
///   identifier-shaped data that may correlate to a user identity
///   (fingerprint, key id, label, file path).
/// * Never log SecureBytes contents, decoded passphrases, quality
///   scores, or any value originating from a `D` line. The
///   private-marker policy is a backstop — the *primary* guard is
///   "do not interpolate it at all."
///
/// `os_log` defaults the privacy of an interpolated `String` to
/// PUBLIC in release builds; an unmarked interpolation therefore
/// surfaces in `log show` even with no debugger attached. The
/// convention above forecloses that regression.
private let log = Logger(subsystem: "org.whitworth.pinentry-darwin", category: "assuan")

// MARK: - DialogState

/// Per-request state accumulated from SET* commands. Reset on RESET. Some
/// fields (notably `error`) are also cleared after the request that consumes
/// them, matching upstream pinentry's "error message is one-shot" behaviour.
private struct DialogState {
    var description: String?
    var prompt: String?
    var title: String?
    var error: String?

    var okLabel: String?
    var notOKLabel: String?
    var cancelLabel: String?

    var keyInfo: Command.KeyInfo?

    var repeatPrompt: String?
    var repeatError: String?
    var repeatOK: String?

    var timeoutSeconds: Int?

    var qualityBar: String?
    var qualityBarTooltip: String?

    var genpinLabel: String?
    var genpinTooltip: String?

    /// Reset everything except the OptionState mirror — RESET clears request
    /// state but option negotiation persists across the session.
    mutating func resetAll() {
        description = nil
        prompt = nil
        title = nil
        error = nil
        okLabel = nil
        notOKLabel = nil
        cancelLabel = nil
        keyInfo = nil
        repeatPrompt = nil
        repeatError = nil
        repeatOK = nil
        timeoutSeconds = nil
        qualityBar = nil
        qualityBarTooltip = nil
        genpinLabel = nil
        genpinTooltip = nil
    }
}

// MARK: - AssuanLoop

@MainActor
final class AssuanLoop {

    // MARK: Stored

    private let session: Session
    private let coordinator: PinentryCoordinator
    private let keychain: KeychainStore
    private let prefs: UserPrefs

    /// Latest accumulated OPTION state.
    private var optionState = OptionState()
    /// Per-request strings/labels.
    private var dialog = DialogState()

    /// Set after a GETPIN that returned a cached entry. If gpg-agent asks
    /// again in the same session it means the cached value was wrong — skip
    /// the cache and fall through to the UI.
    private var triedKeychainThisSession = false

    /// KC-9: per-session counter for CLEARPASSPHRASE. The verb is
    /// unauthenticated and a hostile peer could otherwise spam it as
    /// a denial-of-cache loop, forcing repeated UI prompts. The cap is
    /// generous (well above any legitimate workflow needs) but bounded.
    private var clearPassphraseCount = 0
    private static let maxClearPassphrasePerSession = 64

    // MARK: Init

    init(
        session: Session,
        coordinator: PinentryCoordinator,
        keychain: KeychainStore,
        prefs: UserPrefs
    ) {
        self.session = session
        self.coordinator = coordinator
        self.keychain = keychain
        self.prefs = prefs
    }

    // MARK: Run

    /// Drive the session to completion. Returns when BYE is received or the
    /// peer closes stdin (which `Session.nextCommand()` reports as `.bye`).
    func run() async {
        do {
            try await session.emitGreeting()
        } catch {
            log.error("greeting send failed; bailing out")
            return
        }

        while true {
            let cmd: Command
            do {
                cmd = try await session.nextCommand()
            } catch SessionError.malformedLine {
                // AS-4: malformed input is per-command per the Assuan spec;
                // an ERR reply must NOT tear down the session. The body is
                // intentionally generic (no echo of the offending bytes —
                // that would re-introduce the M8 hardening regression).
                _ = try? await sendErr(code: AssuanError.general,
                                       message: "Malformed command")
                continue
            } catch SessionError.unexpectedEOF {
                // Peer closed gracefully mid-line; treat as BYE.
                return
            } catch {
                log.error("nextCommand threw fatally; aborting loop")
                _ = try? await sendErr(code: AssuanError.general,
                                       message: "internal error")
                return
            }

            switch cmd {
            case .bye:
                _ = try? await session.send(.ok)
                return

            case .reset:
                dialog.resetAll()
                triedKeychainThisSession = false
                await reply(.ok)

            case .option(let key, let value):
                optionState.apply(key: key, value: value)
                await reply(.ok)

            case .setDesc(let s):
                dialog.description = s
                await reply(.ok)
            case .setPrompt(let s):
                dialog.prompt = Mnemonic.strip(s)
                await reply(.ok)
            case .setTitle(let s):
                dialog.title = s
                await reply(.ok)
            case .setError(let s):
                dialog.error = s
                await reply(.ok)
            case .setOK(let s):
                dialog.okLabel = Mnemonic.strip(s)
                await reply(.ok)
            case .setNotOK(let s):
                dialog.notOKLabel = Mnemonic.strip(s)
                await reply(.ok)
            case .setCancel(let s):
                dialog.cancelLabel = Mnemonic.strip(s)
                await reply(.ok)

            case .setKeyInfo(let ki):
                switch ki {
                case .clear:
                    dialog.keyInfo = nil
                case .key:
                    dialog.keyInfo = ki
                }
                await reply(.ok)

            case .setRepeat(let s):
                dialog.repeatPrompt = Mnemonic.strip(s)
                await reply(.ok)
            case .setRepeatOK(let s):
                dialog.repeatOK = Mnemonic.strip(s)
                await reply(.ok)
            case .setRepeatError(let s):
                dialog.repeatError = s
                await reply(.ok)

            case .setTimeout(let n):
                dialog.timeoutSeconds = n
                await reply(.ok)

            case .setQualityBar(let label):
                dialog.qualityBar = label.map(Mnemonic.strip) ?? ""
                await reply(.ok)
            case .setQualityBarTT(let s):
                dialog.qualityBarTooltip = s
                await reply(.ok)

            case .setGenpinLabel(let s):
                // Stub: stored for future v1.1 generation UI.
                dialog.genpinLabel = s
                await reply(.ok)
            case .setGenpinTT(let s):
                dialog.genpinTooltip = s
                await reply(.ok)

            case .getPin:
                await handleGetPin()

            case .confirm(let oneButton):
                await handleConfirm(oneButton: oneButton)

            case .message:
                await handleMessage()

            case .getInfo(let topic):
                await handleGetInfo(topic)

            case .clearPassphrase(let keyInfo):
                handleClearPassphrase(keyInfo)
                await reply(.ok)

            case .unknown:
                // Don't echo the verb back: the parser already strips
                // LF (Session.readLine) but the verb can still carry
                // NUL/BEL/ESC and arbitrary UTF-8 bytes that survived
                // String validation. A constant body keeps log
                // consumers safe and removes a small reconnaissance
                // gadget for hostile parents.
                await reply(.err(code: AssuanError.general,
                                 message: "Unknown command"))
            }
        }
    }

    // MARK: GETPIN

    private func handleGetPin() async {
        // 1. Cache lookup, if eligible and not yet tried this session.
        if !triedKeychainThisSession,
           case .key(_, let fpr)? = dialog.keyInfo,
           optionState.allowExternalPasswordCache,
           prefs.keychainEnabled
        {
            triedKeychainThisSession = true
            do {
                if let cached = try keychain.lookup(fingerprint: fpr) {
                    log.info("returning cached passphrase from keychain")
                    await reply(.status(keyword: "PASSWORD_FROM_CACHE",
                                        parameters: ""))
                    await reply(.data(cached))
                    await reply(.ok)
                    dialog.error = nil
                    return
                }
            } catch let kse as KeychainStoreError {
                // Lookup failures are non-fatal — fall through to UI.
                // OSStatus is non-sensitive and helps post-mortem diagnosis
                // when the cache path silently degrades (e.g. errSec
                // MissingEntitlement on an ad-hoc-signed dev build).
                log.error("keychain lookup failed: \(Self.describe(kse), privacy: .public); falling back to UI")
            } catch {
                log.error("keychain lookup failed; falling back to UI")
            }
        }

        // 2. Build spec and present.
        let spec = buildPinSpec()
        let result = await coordinator.present(spec)

        switch result {
        case .pin(let secure, let savedToKeychain):
            // Optional store-on-submit. Best effort: any failure is logged
            // but does not prevent us from returning the passphrase.
            //
            // Diagnostic logging: emit one info line per submit naming
            // which gate the store path took. The fingerprint is logged
            // .private (correlates to the user's keys) but the gate
            // outcome is .public so post-mortems can tell at a glance
            // whether the user ticked Save in Keychain, whether the spec
            // had a keyinfo, and whether the user disabled the cache.
            if savedToKeychain,
               case .key(_, let fpr)? = dialog.keyInfo,
               prefs.keychainEnabled
            {
                // KC-7: do NOT use the parsed user-id as kSecAttrLabel.
                // The label is visible in Keychain Access metadata
                // (clear-text browsable by any same-user process), so
                // shipping a mailbox-form user-id leaks PII. Use a
                // generic, fingerprint-anchored label instead. The
                // user-id can still be derived offline by anyone who
                // already has the fingerprint.
                let label = "GnuPG passphrase (\(fpr.prefix(16)))"
                do {
                    try keychain.store(fingerprint: fpr,
                                       label: label,
                                       passphrase: secure)
                    log.info("keychain store ok; fingerprint=\(fpr, privacy: .private)")
                } catch let kse as KeychainStoreError {
                    log.error("keychain store failed: \(Self.describe(kse), privacy: .public); passphrase not cached")
                } catch {
                    log.error("keychain store failed (unknown); passphrase not cached")
                }
            } else {
                // Diagnostic: explain why we skipped the store path so
                // post-mortems can tell apart "user unticked Save",
                // "no SETKEYINFO", and "keychainEnabled=false".
                let why: String
                if !savedToKeychain {
                    why = "user-unchecked-save"
                } else if dialog.keyInfo == nil {
                    why = "no-keyinfo"
                } else {
                    why = "prefs-disabled"
                }
                log.info("keychain store skipped: \(why, privacy: .public)")
            }

            await reply(.data(secure))
            if dialog.repeatPrompt != nil {
                await reply(.status(keyword: "PIN_REPEATED", parameters: ""))
            }
            await reply(.ok)

        case .canceled:
            await reply(.err(code: AssuanError.canceled,
                             message: "Operation cancelled"))

        case .windowClosed:
            await reply(.status(keyword: "BUTTON_INFO", parameters: "close"))
            await reply(.err(code: AssuanError.canceled,
                             message: "Operation cancelled"))

        case .timedOut:
            await reply(.err(code: AssuanError.canceled,
                             message: "Operation timed out"))

        case .confirmed, .notConfirmed:
            // These should not reach a GETPIN flow; treat as cancel.
            await reply(.err(code: AssuanError.canceled,
                             message: "Operation cancelled"))
        }

        // Per upstream: clear the one-shot error after each GETPIN.
        dialog.error = nil
    }

    // MARK: CONFIRM

    private func handleConfirm(oneButton: Bool) async {
        let spec = buildConfirmSpec(oneButton: oneButton)
        let result = await coordinator.present(spec)

        switch result {
        case .confirmed:
            await reply(.ok)
        case .notConfirmed:
            await reply(.err(code: AssuanError.notConfirmed,
                             message: "Not confirmed"))
        case .canceled:
            await reply(.err(code: AssuanError.canceled,
                             message: "Operation cancelled"))
        case .windowClosed:
            await reply(.status(keyword: "BUTTON_INFO", parameters: "close"))
            await reply(.err(code: AssuanError.canceled,
                             message: "Operation cancelled"))
        case .timedOut:
            await reply(.err(code: AssuanError.canceled,
                             message: "Operation timed out"))
        case .pin:
            // Should not occur for CONFIRM; treat as cancel.
            await reply(.err(code: AssuanError.canceled,
                             message: "Operation cancelled"))
        }

        dialog.error = nil
    }

    // MARK: MESSAGE

    private func handleMessage() async {
        let spec = buildMessageSpec()
        // MESSAGE is a single-OK acknowledgement; coordinator's MessageView
        // returns .confirmed. Whatever comes back, MESSAGE always resolves
        // with OK (no ERR variant) to match upstream behaviour.
        _ = await coordinator.present(spec)
        await reply(.ok)
        dialog.error = nil
    }

    // MARK: GETINFO

    private func handleGetInfo(_ topic: Command.GetInfoTopic) async {
        switch topic {
        case .version:
            await sendInfoLine(resolvedVersion())
        case .pid:
            await sendInfoLine(String(getpid()))
        case .flavor:
            await sendInfoLine("darwin")
        case .ttyinfo:
            // AS-8: cap each field so the combined `D <n> <t> 0\n` line
            // stays under LineCodec.maxLineLength even when ttyName /
            // ttyType were inflated by a hostile OPTION shipment.
            // Single-field cap of 256 leaves room for separators + flag.
            let name = Self.cap(optionState.ttyName ?? "-", to: 256)
            let type = Self.cap(optionState.ttyType ?? "-", to: 256)
            // Last field is `is_emacs` — always 0 for us.
            await sendInfoLine("\(name) \(type) 0")
        case .other:
            await reply(.err(code: AssuanError.general,
                             message: "unknown getinfo"))
        }
    }

    /// AS-8 helper: byte-bounded prefix. `String.prefix` counts in
    /// extended-grapheme clusters which can be many bytes apiece; we
    /// need a byte cap to stay under the wire-line limit.
    private static func cap(_ s: String, to maxBytes: Int) -> String {
        if s.utf8.count <= maxBytes { return s }
        var out = String.UnicodeScalarView()
        var used = 0
        for scalar in s.unicodeScalars {
            let n = String(scalar).utf8.count
            if used + n > maxBytes { break }
            out.append(scalar)
            used += n
        }
        return String(out)
    }

    /// Encode an ASCII info string into a `D` line + OK. The payload is
    /// non-secret (GETINFO version, pid, ttyinfo) so we route through
    /// `Response.dataPlaintext(_ Data)` instead of allocating an
    /// mlock'd SecureBytes for it. Architecturally distinct from the
    /// `Response.data(SecureBytes)` path so a code reviewer can spot
    /// any future regression that puts a secret on the plaintext path.
    private func sendInfoLine(_ value: String) async {
        if value.isEmpty {
            await reply(.ok)
            return
        }
        await reply(.dataPlaintext(Data(value.utf8)))
        await reply(.ok)
    }

    // MARK: CLEARPASSPHRASE

    /// Parse `<mode>/<fingerprint>` (or `--clear`) and forget the entry.
    /// Errors are swallowed — CLEARPASSPHRASE is best-effort.
    ///
    /// KC-9: rate-limited per session. A hostile peer that fires
    /// CLEARPASSPHRASE in a tight loop would otherwise force repeated
    /// keychain calls (each potentially prompting the user). Past the
    /// per-session cap we silently no-op and log once.
    private func handleClearPassphrase(_ keyInfo: String) {
        clearPassphraseCount += 1
        if clearPassphraseCount > Self.maxClearPassphrasePerSession {
            if clearPassphraseCount == Self.maxClearPassphrasePerSession + 1 {
                log.error("clearpassphrase: rate limit reached for session; ignoring further requests")
            }
            return
        }
        let trimmed = keyInfo.trimmingCharacters(in: .whitespaces)
        if trimmed.isEmpty || trimmed == "--clear" {
            return
        }
        guard let slash = trimmed.firstIndex(of: "/") else {
            return
        }
        let fpr = String(trimmed[trimmed.index(after: slash)...])
        if fpr.isEmpty { return }
        // Mirror SETKEYINFO's strict validation. CLEARPASSPHRASE is
        // best-effort, so an invalid fingerprint silently no-ops rather
        // than aborting the loop — but we still refuse to flow attacker
        // bytes into kSecAttrAccount.
        guard Command.isValidFingerprint(fpr) else {
            log.error("clearpassphrase: invalid fingerprint format; ignoring")
            return
        }
        do {
            try keychain.clear(fingerprint: fpr)
        } catch {
            log.error("keychain clear failed for clearpassphrase")
        }
    }

    // MARK: Spec builders

    private func buildPinSpec() -> DialogSpec {
        var defaults = DialogSpec.DefaultLabels()
        if let v = optionState.defaultOK { defaults.ok = v }
        if let v = optionState.defaultCancel { defaults.cancel = v }
        if let v = optionState.defaultPrompt { defaults.prompt = v }

        let keyInfo: DialogSpec.KeyInfo?
        if case .key(let mode, let fpr)? = dialog.keyInfo {
            keyInfo = .key(mode: mode, fingerprint: fpr)
        } else {
            keyInfo = nil
        }

        // Match pinentry-mac: show Save in Keychain for any keyinfo mode
        // except 'u' (user-managed). gpg-agent's OPTION
        // allow-external-password-cache is informational only; pinentry-mac
        // ignores it and we follow suit so existing GPGTools users see the
        // same UX they're used to.
        let allowSave = DialogSpec.canSaveToKeychain(
            keyInfo: keyInfo,
            keychainEnabled: prefs.keychainEnabled
        )

        return DialogSpec(
            kind: .pin,
            title: dialog.title,
            description: dialog.description,
            prompt: dialog.prompt,
            error: dialog.error,
            okLabel: dialog.okLabel,
            notOKLabel: dialog.notOKLabel,
            cancelLabel: dialog.cancelLabel,
            repeatPrompt: dialog.repeatPrompt,
            repeatError: dialog.repeatError,
            repeatOK: dialog.repeatOK,
            qualityBarLabel: dialog.qualityBar,
            qualityBarTooltip: dialog.qualityBarTooltip,
            keyInfo: keyInfo,
            allowKeychainSave: allowSave,
            timeoutSeconds: dialog.timeoutSeconds,
            defaults: defaults
        )
    }

    private func buildConfirmSpec(oneButton: Bool) -> DialogSpec {
        var defaults = DialogSpec.DefaultLabels()
        if let v = optionState.defaultOK { defaults.ok = v }
        if let v = optionState.defaultCancel { defaults.cancel = v }
        if let v = optionState.defaultPrompt { defaults.prompt = v }

        return DialogSpec(
            kind: .confirm(oneButton: oneButton),
            title: dialog.title,
            description: dialog.description,
            prompt: dialog.prompt,
            error: dialog.error,
            okLabel: dialog.okLabel,
            notOKLabel: dialog.notOKLabel,
            cancelLabel: dialog.cancelLabel,
            timeoutSeconds: dialog.timeoutSeconds,
            defaults: defaults
        )
    }

    private func buildMessageSpec() -> DialogSpec {
        var defaults = DialogSpec.DefaultLabels()
        if let v = optionState.defaultOK { defaults.ok = v }

        return DialogSpec(
            kind: .message,
            title: dialog.title,
            description: dialog.description,
            error: dialog.error,
            okLabel: dialog.okLabel,
            timeoutSeconds: dialog.timeoutSeconds,
            defaults: defaults
        )
    }

    // MARK: - Send helpers

    /// Send a response, swallowing IO errors (they almost always mean the
    /// peer closed; the next read will surface that as EOF / .bye).
    private func reply(_ response: Response) async {
        do {
            try await session.send(response)
        } catch {
            log.error("send failed; peer probably gone")
        }
    }

    /// Last-ditch error send — used when we want to know whether stdout is
    /// still alive. Returns the result of the underlying call.
    private func sendErr(code: UInt32, message: String) async throws {
        try await session.send(.err(code: code, message: message))
    }

    /// Render a `KeychainStoreError` as a short non-sensitive string for
    /// os_log. Includes the OSStatus when present so future regressions
    /// (e.g. errSecMissingEntitlement = -34018 on an ad-hoc dev build,
    /// or errSecAuthFailed = -25293 on a stale ACL) are diagnosable from
    /// `log show` without re-running the failing flow under a debugger.
    static func describe(_ error: KeychainStoreError) -> String {
        switch error {
        case .userCanceled:
            return "userCanceled"
        case .unexpectedStatus(let s):
            return "unexpectedStatus(\(s))"
        case .degradedNoEntitlement:
            return "degradedNoEntitlement"
        case .accessControlFailed(let detail):
            // Detail comes from CFError describing why
            // SecAccessControlCreateWithFlags returned nil. Marked
            // .private at all interpolation sites; here we return the
            // raw text and rely on each call site's privacy modifier.
            return "accessControlFailed(\(detail))"
        }
    }
}

// User-id extraction lives in `Command.parseUserIdFromDescription`
// (Sources/AssuanProtocol/Command.swift) so it is testable from the
// AssuanProtocol test target. The bounded, last-quoted-pair version
// also rejects control bytes that would otherwise corrupt
// kSecAttrLabel and Keychain Access display.

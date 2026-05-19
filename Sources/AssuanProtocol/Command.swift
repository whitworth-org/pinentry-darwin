// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// Command.swift — typed representation of every Assuan command pinentry
// understands. The verbs and their semantics are taken from the upstream
// dispatch table in /Users/rwhitworth/Development/pinentry/pinentry/pinentry.c
// lines 1306–1994 (the cmd_* handlers and `register_commands`).
//
// `Command.parse` decodes one already-LF-stripped line. Argument bodies are
// percent-decoded as UTF-8 text (these are user-visible labels, not raw
// bytes — `D`-line PIN payloads use a different, SecureBytes-backed path
// in `Session`).

import Foundation

// MARK: - Command

public enum Command: Equatable, Sendable {
    case bye
    case reset
    case option(key: String, value: String?)
    case setDesc(String)
    case setPrompt(String)
    case setTitle(String)
    case setError(String)
    case setOK(String)
    case setNotOK(String)
    case setCancel(String)
    case setKeyInfo(KeyInfo)
    case setRepeat(String)
    case setRepeatOK(String)
    case setRepeatError(String)
    case setTimeout(Int)
    case setQualityBar(String?)
    case setQualityBarTT(String)
    case setGenpinLabel(String)
    case setGenpinTT(String)
    case getPin
    case confirm(oneButton: Bool)
    case message
    case getInfo(GetInfoTopic)
    case clearPassphrase(keyInfo: String)
    case unknown(verb: String, args: String)

    public enum KeyInfo: Equatable, Sendable {
        case clear
        case key(mode: Character, fingerprint: String)
    }

    public enum GetInfoTopic: Equatable, Sendable {
        case version
        case pid
        case flavor
        case ttyinfo
        case other(String)
    }
}

// MARK: - Errors

public enum CommandParseError: Error, Equatable {
    case malformed(String)
    case unsupportedKeyInfo
}

// MARK: - Parsing

extension Command {

    /// Parse one decoded Assuan line (LF already stripped). Returns
    /// `.unknown` for verbs we don't recognise so the session can reply with
    /// `ERR` rather than tearing down the connection.
    public static func parse(_ line: String) throws -> Command {
        // Trim ASCII whitespace from both ends. Assuan lines are ASCII, so
        // this is byte-cheap and matches upstream's leading-space skip.
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        if trimmed.isEmpty {
            throw CommandParseError.malformed("empty line")
        }

        // Split into verb / args on the first ASCII space.
        let (verb, rawArgs) = splitVerbArgs(trimmed)
        let upper = verb.uppercased()

        switch upper {
        case "BYE":
            return .bye
        case "RESET":
            return .reset
        case "NOP":
            // `NOP` is part of the Assuan core. We don't model it explicitly —
            // surface as unknown so the session replies with a plain OK if
            // upstream callers ever start sending it.
            return .unknown(verb: upper, args: rawArgs)
        case "OPTION":
            return try parseOption(rawArgs)
        case "SETDESC":
            return .setDesc(try decodeArg(rawArgs))
        case "SETPROMPT":
            return .setPrompt(try decodeArg(rawArgs))
        case "SETTITLE":
            return .setTitle(try decodeArg(rawArgs))
        case "SETERROR":
            return .setError(try decodeArg(rawArgs))
        case "SETOK":
            return .setOK(try decodeArg(rawArgs))
        case "SETNOTOK":
            return .setNotOK(try decodeArg(rawArgs))
        case "SETCANCEL":
            return .setCancel(try decodeArg(rawArgs))
        case "SETKEYINFO":
            return try parseSetKeyInfo(rawArgs)
        case "SETREPEAT":
            return .setRepeat(try decodeArg(rawArgs))
        case "SETREPEATOK":
            return .setRepeatOK(try decodeArg(rawArgs))
        case "SETREPEATERROR":
            return .setRepeatError(try decodeArg(rawArgs))
        case "SETTIMEOUT":
            return try parseSetTimeout(rawArgs)
        case "SETQUALITYBAR":
            // Argument is optional: bare command means "show the bar with no
            // tooltip"; with text it sets the label.
            let decoded = try decodeArg(rawArgs)
            return .setQualityBar(decoded.isEmpty ? nil : decoded)
        case "SETQUALITYBAR_TT":
            return .setQualityBarTT(try decodeArg(rawArgs))
        case "SETGENPIN":
            return .setGenpinLabel(try decodeArg(rawArgs))
        case "SETGENPIN_TT":
            return .setGenpinTT(try decodeArg(rawArgs))
        case "GETPIN":
            return .getPin
        case "CONFIRM":
            return parseConfirm(rawArgs)
        case "MESSAGE":
            return .message
        case "GETINFO":
            return parseGetInfo(rawArgs)
        case "CLEARPASSPHRASE":
            // Upstream passes the cache id through verbatim — it may legally
            // contain things like `--mode=normal`, so we don't escape-decode.
            let id = rawArgs.trimmingCharacters(in: .whitespaces)
            return .clearPassphrase(keyInfo: id)
        default:
            return .unknown(verb: upper, args: rawArgs)
        }
    }

    // MARK: Sub-parsers

    private static func parseOption(_ args: String) throws -> Command {
        // OPTION accepts both `key=value` and `key value`. With no value at
        // all (just `OPTION key`) value is nil.
        let trimmed = args.trimmingCharacters(in: .whitespaces)
        if trimmed.isEmpty {
            throw CommandParseError.malformed("OPTION without key")
        }

        // Prefer `=` because some keys legitimately contain values that
        // start with spaces — though in practice the wire form is one or the
        // other, never both.
        if let eqIdx = trimmed.firstIndex(of: "=") {
            let key = String(trimmed[..<eqIdx])
            let valueRaw = String(trimmed[trimmed.index(after: eqIdx)...])
            let value = try decodeArg(valueRaw)
            return .option(key: key, value: value)
        }

        if let spaceIdx = trimmed.firstIndex(of: " ") {
            let key = String(trimmed[..<spaceIdx])
            let valueRaw = String(trimmed[trimmed.index(after: spaceIdx)...])
                .trimmingCharacters(in: .whitespaces)
            let value = try decodeArg(valueRaw)
            return .option(key: key, value: value)
        }

        return .option(key: trimmed, value: nil)
    }

    private static func parseSetKeyInfo(_ args: String) throws -> Command {
        let trimmed = args.trimmingCharacters(in: .whitespaces)
        if trimmed == "--clear" {
            return .setKeyInfo(.clear)
        }
        // Upstream form: "<mode>/<fingerprint>" where <mode> is one ASCII
        // letter (`u`, `s`, `n`, etc).
        guard let slashIdx = trimmed.firstIndex(of: "/") else {
            throw CommandParseError.unsupportedKeyInfo
        }
        let modeStr = trimmed[..<slashIdx]
        // SECURITY (AS-1): validate strictly as a single ASCII letter and
        // normalise to lowercase. Swift `Character.count == 1` accepts
        // multi-scalar grapheme clusters (e.g. `u + U+0301`) and is
        // case-sensitive, both of which let a hostile gpg-agent bypass the
        // `mode == "u"` no-cache policy in `Spec.canSaveToKeychain`. By
        // requiring exactly one ASCII letter and lowercasing it, every
        // unicode-homoglyph or uppercase form either rejects (non-letter)
        // or canonicalises to the policy-checked value.
        guard
            modeStr.unicodeScalars.count == 1,
            let scalar = modeStr.unicodeScalars.first,
            (0x41...0x5A).contains(scalar.value) || (0x61...0x7A).contains(scalar.value)
        else {
            throw CommandParseError.unsupportedKeyInfo
        }
        let lowered = scalar.value | 0x20  // ASCII to-lower (safe: range guarded)
        let modeChar = Character(Unicode.Scalar(lowered)!)
        let fpr = String(trimmed[trimmed.index(after: slashIdx)...])
        if fpr.isEmpty {
            throw CommandParseError.unsupportedKeyInfo
        }
        // The fingerprint flows directly into kSecAttrAccount in the
        // shared "GnuPG" keychain namespace. Reject anything that isn't a
        // SHA-1 (40) or SHA-256 (64) hex string so a hostile parent
        // cannot pollute the namespace with control bytes, slashes, or
        // megabyte-scale payloads.
        guard isValidFingerprint(fpr) else {
            throw CommandParseError.unsupportedKeyInfo
        }
        return .setKeyInfo(.key(mode: modeChar, fingerprint: fpr))
    }

    /// Hex-fingerprint validator shared by `parseSetKeyInfo` and the
    /// CLEARPASSPHRASE handler. Accepts exactly 40 (SHA-1) or 64 (SHA-256)
    /// case-insensitive ASCII hex characters; rejects everything else
    /// (length, non-hex bytes, Unicode hex digits from other scripts).
    public static func isValidFingerprint(_ s: String) -> Bool {
        let n = s.count
        guard n == 40 || n == 64 else { return false }
        return s.unicodeScalars.allSatisfy { c in
            let v = c.value
            return (v >= 0x30 && v <= 0x39) ||  // 0-9
                   (v >= 0x41 && v <= 0x46) ||  // A-F
                   (v >= 0x61 && v <= 0x66)     // a-f
        }
    }

    private static func parseSetTimeout(_ args: String) throws -> Command {
        let trimmed = args.trimmingCharacters(in: .whitespaces)
        guard let n = Int(trimmed) else {
            throw CommandParseError.malformed("SETTIMEOUT requires an integer")
        }
        return .setTimeout(n)
    }

    private static func parseConfirm(_ args: String) -> Command {
        let trimmed = args.trimmingCharacters(in: .whitespaces)
        // CONFIRM accepts `--one-button` as a flag; anything else (including
        // a description argument) is ignored at parse time — upstream pulls
        // its description from a prior SETDESC.
        let oneButton = trimmed.split(separator: " ")
            .contains(where: { $0 == "--one-button" })
        return .confirm(oneButton: oneButton)
    }

    private static func parseGetInfo(_ args: String) -> Command {
        let topic = args.trimmingCharacters(in: .whitespaces).lowercased()
        switch topic {
        case "version": return .getInfo(.version)
        case "pid":     return .getInfo(.pid)
        case "flavor":  return .getInfo(.flavor)
        case "ttyinfo": return .getInfo(.ttyinfo)
        default:        return .getInfo(.other(topic))
        }
    }

    // MARK: Utilities

    private static func splitVerbArgs(_ line: String) -> (verb: String, args: String) {
        if let spaceIdx = line.firstIndex(of: " ") {
            let verb = String(line[..<spaceIdx])
            let args = String(line[line.index(after: spaceIdx)...])
            return (verb, args)
        }
        return (line, "")
    }

    /// Percent-decode a textual argument. We treat the result as UTF-8;
    /// unrepresentable byte sequences are rejected.
    private static func decodeArg(_ raw: String) throws -> String {
        let trimmed = raw.trimmingCharacters(in: .whitespaces)
        if trimmed.isEmpty { return "" }
        do {
            let bytes = try LineCodec.unescape(trimmed)
            guard let s = String(bytes: bytes, encoding: .utf8) else {
                throw CommandParseError.malformed("invalid UTF-8 in argument")
            }
            return s
        } catch let e as LineCodec.DecodeError {
            throw CommandParseError.malformed("escape error: \(e)")
        }
    }
}

// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// Response.swift — typed Assuan reply lines, plus the well-known gpg-error
// codes pinentry needs to emit (canceled / not-confirmed / locale-problem /
// general).
//
// Encoding rules:
//   * `OK` is bare; `OK <text>` carries an optional comment.
//   * `D <escaped-payload>` carries data; for PIN bytes we route through
//     `SecureBytes.withUnsafeBytes` and emit the wire bytes into a
//     SecureBytes-backed scratch buffer (mlock'd, deinit-zeroed) so the
//     escaped form never lives in unwiped Foundation.Data heap (SL-1).
//   * `S <KEYWORD> <params>` carries a status update.
//   * `ERR <decimal-code> <message>` carries an error.
//   * `# ...` is a comment — we never emit one for PIN data.
//
// Length budget (FZ-1):
//   The Assuan wire-line limit is 1000 bytes excluding LF. A `D` payload
//   has a 2-byte verb prefix (`D `) and a 1-byte LF suffix, leaving 997
//   bytes for the escaped payload. Each source byte costs at most 3
//   wire bytes (`%HH`), so the maximum source bytes per single line is
//   332. Per the Assuan spec, oversized payloads are split across
//   consecutive `D` lines which the receiver concatenates verbatim
//   before returning to the caller. `wirePayloads()` therefore returns
//   one `D` payload per chunk.

import Foundation
import Darwin
import SecureMemory

// MARK: - WirePayload

/// A single ready-to-write wire line. Variants reflect the
/// confidentiality requirement of the bytes:
///   - `.plain(Data)` — ordinary heap; safe for greetings, status lines,
///     ERR, comments, and non-secret `D` payloads (GETINFO etc.).
///   - `.secret(SecureBytes)` — wire bytes for a secret `D` line live in
///     mlock'd, deinit-zeroed storage so the escaped passphrase (which
///     is byte-identical to the plaintext for ASCII passphrases) is not
///     left in the unwiped Foundation.Data heap. The Session writes
///     these directly via `Darwin.write()` from inside
///     `SecureBytes.withUnsafeBytes`.
public enum WirePayload: Sendable {
    case plain(Data)
    case secret(SecureBytes)
}

// MARK: - Response

public enum Response: Sendable {
    case ok
    case okWithComment(String)
    /// `D <escaped-bytes>` for SECRET payloads. Backed by SecureBytes
    /// (mlock'd, deinit-zeroed). Use this for any value whose plaintext
    /// must not linger in unwiped heap. Long payloads are split across
    /// continuation `D` lines per the Assuan spec (FZ-1).
    case data(SecureBytes)
    /// `D <escaped-bytes>` for NON-SECRET payloads (GETINFO version,
    /// pid, ttyinfo, etc.). Backed by a plain `Data` so we don't waste
    /// an mlock'd page on bytes that aren't sensitive. Architecturally
    /// distinct from `data(SecureBytes)` so a code reviewer can spot a
    /// secret being routed through the wrong constructor.
    case dataPlaintext(Data)
    case status(keyword: String, parameters: String)
    case err(code: UInt32, message: String)
    case comment(String)
}

// MARK: - Error codes

public enum AssuanError {
    /// `GPG_ERR_CANCELED` — user dismissed the dialog.
    public static let canceled: UInt32 = 83886090
    /// `GPG_ERR_NOT_CONFIRMED` — confirm dialog returned "No".
    public static let notConfirmed: UInt32 = 83886091
    /// `GPG_ERR_LOCALE_PROBLEM` — locale setup failed.
    public static let localeProblem: UInt32 = 83886084
    /// `GPG_ERR_GENERAL` — fallback when nothing more specific applies.
    public static let general: UInt32 = 83886126
}

// MARK: - Wire encoding

extension Response {

    /// Encode this response as one or more LF-terminated wire payloads
    /// in the order the caller must transmit. Each element is one
    /// complete line ready to be written without further processing.
    ///
    /// FZ-1: secret `D` payloads larger than the per-line escape budget
    /// (`maxSourceBytesPerDataLine`) are split across continuation `D`
    /// lines. Per the Assuan "Data Lines" spec the receiver
    /// concatenates them verbatim.
    public func wirePayloads() -> [WirePayload] {
        switch self {
        case .ok:
            return [.plain(lineData(prefix: "OK", body: nil))]

        case .okWithComment(let text):
            return [.plain(lineData(prefix: "OK", body: text))]

        case .status(let keyword, let parameters):
            let body = parameters.isEmpty ? keyword : "\(keyword) \(parameters)"
            return [.plain(lineData(prefix: "S", body: body))]

        case .err(let code, let message):
            let body = "\(code) \(message)"
            return [.plain(lineData(prefix: "ERR", body: body))]

        case .comment(let text):
            return [.plain(lineData(prefix: "#", body: text))]

        case .data(let secure):
            return encodeSecretDataLines(secure)

        case .dataPlaintext(let data):
            return encodePlaintextDataLines(data).map { WirePayload.plain($0) }
        }
    }

    /// Backwards-compatibility shim. Old callers that only handle
    /// `Data` payloads get the legacy view: secret payloads are
    /// materialised into ordinary Data, defeating the SL-1 guarantee.
    /// New code must use `wirePayloads()` and the Session
    /// `writeAll(_:WirePayload)` path. Marked deprecated to keep an
    /// audit trail of any caller still on the old API.
    @available(*, deprecated, message: "Use wirePayloads() so secret payloads stay in SecureBytes.")
    public func wireLines() -> [Data] {
        wirePayloads().map { payload -> Data in
            switch payload {
            case .plain(let d): return d
            case .secret(let secure):
                // Last-resort copy. New code must NOT take this path.
                return secure.withUnsafeBytes { Data($0) }
            }
        }
    }

    // MARK: - Helpers

    /// Maximum source bytes per single secret `D` line. Each source
    /// byte may expand 3-for-1 to `%HH`, plus the `D ` prefix and the
    /// LF terminator. Wire-line cap is 1000 excluding LF.
    ///   2 (`D `) + 3*N (escape worst case) + 1 (LF) ≤ 1001
    ///   → N ≤ 332
    static let maxSourceBytesPerDataLine: Int = 332

    /// Build a "VERB body\n" wire line as `Data`. Never used for secret
    /// payloads — those go through `encodeSecretDataLines` exclusively.
    ///
    /// AS-3: assert that `body` carries no embedded LF/CR/NUL. Today
    /// every call site passes hardcoded text (M8 hardening), so the
    /// precondition is free; it catches future regressions that pipe
    /// attacker-controlled bytes into `body` (which would otherwise let
    /// the attacker forge wire responses by smuggling an LF).
    private func lineData(prefix: String, body: String?) -> Data {
        var d = Data()
        d.append(contentsOf: prefix.utf8)
        if let body, !body.isEmpty {
            // AS-3 boundary check. Also reject 0x7F DEL out of an
            // abundance of caution — it has no business in a verb body
            // and signals a malformed caller.
            for b in body.utf8 {
                precondition(
                    b != 0x0A && b != 0x0D && b != 0x00 && b != 0x7F,
                    "Response.lineData body must not contain LF/CR/NUL/DEL"
                )
            }
            d.append(0x20) // space
            d.append(contentsOf: body.utf8)
        }
        d.append(0x0A) // LF
        return d
    }

    /// SL-1 / FZ-1: encode a `D` line carrying a SecureBytes payload.
    ///
    /// The escaped wire bytes are written into a SecureBytes-backed
    /// scratch buffer so the cleartext-equivalent (for ASCII passphrases
    /// the escaped form is byte-identical to the plaintext) never
    /// materialises in unwiped Foundation.Data heap. Long payloads are
    /// split into continuation `D` lines per the Assuan spec.
    ///
    /// CRITICAL: data-line escaping must NOT remap space → '+'. The
    /// '+' substitution is a command-argument convention only; per the
    /// Assuan spec, `D` payloads carry spaces verbatim. Using the
    /// command-arg encoder here would corrupt any passphrase that
    /// contained a space.
    private func encodeSecretDataLines(_ secure: SecureBytes) -> [WirePayload] {
        return secure.withUnsafeBytes { (buf: UnsafeBufferPointer<UInt8>) -> [WirePayload] in
            let total = buf.count
            if total == 0 {
                // Empty payload still needs an empty `D` line so the
                // receiver sees the (zero-length) value — degenerate
                // but well-defined.
                let empty = SecureBytes(capacity: 3)
                empty.append(0x44) // 'D'
                empty.append(0x20) // ' '
                empty.append(0x0A) // LF
                return [.secret(empty)]
            }
            var result: [WirePayload] = []
            var offset = 0
            while offset < total {
                let chunkLen = Swift.min(Self.maxSourceBytesPerDataLine, total - offset)
                let chunkBase = buf.baseAddress!.advanced(by: offset)
                let chunk = UnsafeBufferPointer(start: chunkBase, count: chunkLen)
                // Worst-case escape size: 3 * chunkLen + 3 (`D ` + LF).
                // Cap respects SecureBytes.maxLength (16 KiB), which is
                // far above 3*332+3 = 999.
                let maxOut = 3 * chunkLen + 3
                let lineBuf = SecureBytes(capacity: maxOut)
                lineBuf.append(0x44) // 'D'
                lineBuf.append(0x20) // ' '
                LineCodec.escapeForDataLine(chunk, into: lineBuf)
                lineBuf.append(0x0A) // LF
                result.append(.secret(lineBuf))
                offset += chunkLen
            }
            return result
        }
    }

    /// Encode a `D` line for non-secret payload (GETINFO replies). Same
    /// wire format as `encodeSecretDataLines` but the input buffer is a
    /// regular `Data` — there is no need to allocate (and waste an
    /// mlock page on) a SecureBytes for bytes that are not sensitive.
    /// FZ-1: chunked to respect the wire-line cap.
    private func encodePlaintextDataLines(_ payload: Data) -> [Data] {
        let total = payload.count
        if total == 0 {
            var d = Data()
            d.append(0x44) // 'D'
            d.append(0x20) // ' '
            d.append(0x0A) // LF
            return [d]
        }
        return payload.withUnsafeBytes { (raw: UnsafeRawBufferPointer) -> [Data] in
            guard let base = raw.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                return []
            }
            var result: [Data] = []
            var offset = 0
            while offset < total {
                let chunkLen = Swift.min(Self.maxSourceBytesPerDataLine, total - offset)
                let chunk = UnsafeBufferPointer(start: base.advanced(by: offset), count: chunkLen)
                var d = Data()
                d.reserveCapacity(2 + chunk.count * 3 + 1)
                d.append(0x44) // 'D'
                d.append(0x20) // ' '
                LineCodec.escapeForDataLine(chunk, into: &d)
                d.append(0x0A) // LF
                result.append(d)
                offset += chunkLen
            }
            return result
        }
    }
}

// MARK: - LineCodec / SecureBytes shim

extension LineCodec {
    /// SL-1 sink: append the escaped form of `bytes` into a
    /// SecureBytes-backed wire buffer. Mirrors the
    /// `escapeForDataLine(_:into:Data)` overload; declared here so
    /// LineCodec stays Foundation-only and only this file knows about
    /// the SecureBytes sink.
    static func escapeForDataLine(
        _ bytes: UnsafeBufferPointer<UInt8>,
        into out: SecureBytes
    ) {
        for b in bytes {
            switch b {
            case 0x2B, 0x25, 0..<0x20, 0x7F...0xFF:
                // %HH (uppercase) per upstream `%02X` formatting.
                out.append(0x25) // '%'
                out.append(hexNibble(b >> 4))
                out.append(hexNibble(b & 0x0F))
            default:
                out.append(b)
            }
        }
    }

    @inline(__always)
    private static func hexNibble(_ n: UInt8) -> UInt8 {
        n < 10 ? (0x30 + n) : (0x41 + (n - 10))
    }
}

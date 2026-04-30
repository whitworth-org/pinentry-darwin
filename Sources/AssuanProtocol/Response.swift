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
//     `SecureBytes.withUnsafeBytes` so the plaintext never leaves the secure
//     buffer except as the escaped wire bytes themselves.
//   * `S <KEYWORD> <params>` carries a status update.
//   * `ERR <decimal-code> <message>` carries an error.
//   * `# ...` is a comment — we never emit one for PIN data.

import Foundation
import SecureMemory

// MARK: - Response

public enum Response: Sendable {
    case ok
    case okWithComment(String)
    /// `D <escaped-bytes>` for SECRET payloads. Backed by SecureBytes
    /// (mlock'd, deinit-zeroed). Use this for any value whose plaintext
    /// must not linger in unwiped heap.
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

    /// Encode this response as one or more LF-terminated wire lines. Each
    /// element of the returned array is a single line ready to be written
    /// to the output FileHandle without further processing.
    ///
    /// For `.data`, the PIN bytes are read inside `SecureBytes.withUnsafeBytes`
    /// and the escaped form is emitted directly into a `Data` of bytes —
    /// nothing flows through `Swift.String`. The returned `Data` IS visible
    /// outside the secure buffer (it's the wire form), but the raw plaintext
    /// is never copied into a `String`.
    public func wireLines() -> [Data] {
        switch self {
        case .ok:
            return [lineData(prefix: "OK", body: nil)]

        case .okWithComment(let text):
            return [lineData(prefix: "OK", body: text)]

        case .status(let keyword, let parameters):
            let body = parameters.isEmpty ? keyword : "\(keyword) \(parameters)"
            return [lineData(prefix: "S", body: body)]

        case .err(let code, let message):
            let body = "\(code) \(message)"
            return [lineData(prefix: "ERR", body: body)]

        case .comment(let text):
            return [lineData(prefix: "#", body: text)]

        case .data(let secure):
            return [encodeDataLine(secure)]

        case .dataPlaintext(let data):
            return [encodePlaintextDataLine(data)]
        }
    }

    // MARK: Helpers

    /// Build a "VERB body\n" wire line as `Data`.
    private func lineData(prefix: String, body: String?) -> Data {
        var d = Data()
        d.append(contentsOf: prefix.utf8)
        if let body, !body.isEmpty {
            d.append(0x20) // space
            d.append(contentsOf: body.utf8)
        }
        d.append(0x0A) // LF
        return d
    }

    /// Encode a `D` line carrying SecureBytes payload. Worst-case length is
    /// 2 (for "D ") + 3 * payloadCount (every byte escaped) + 1 (LF).
    /// The escape pipeline writes directly into the wire-output `Data`:
    /// no intermediate `Swift.String` ever holds the escaped bytes
    /// (which, for the common ASCII-passphrase case, are byte-identical
    /// to the plaintext). The `Data` IS the value about to go on the
    /// wire and is dropped immediately after `writeAll`.
    private func encodeDataLine(_ secure: SecureBytes) -> Data {
        // CRITICAL: data-line escaping must NOT remap space → '+'. The
        // '+' substitution is a command-argument convention only; per the
        // Assuan spec, `D` payloads carry spaces verbatim. Using the
        // command-arg encoder here would corrupt any passphrase that
        // contained a space.
        return secure.withUnsafeBytes { (buf: UnsafeBufferPointer<UInt8>) -> Data in
            var d = Data()
            d.reserveCapacity(2 + buf.count * 3 + 1)
            d.append(0x44) // 'D'
            d.append(0x20) // ' '
            LineCodec.escapeForDataLine(buf, into: &d)
            d.append(0x0A) // LF
            return d
        }
    }

    /// Encode a `D` line for non-secret payload (GETINFO replies). Same
    /// wire format as `encodeDataLine(_ secure:)` but the input buffer
    /// is a regular `Data` — there is no need to allocate (and waste an
    /// mlock page on) a SecureBytes for bytes that are not sensitive.
    private func encodePlaintextDataLine(_ payload: Data) -> Data {
        var d = Data()
        d.reserveCapacity(2 + payload.count * 3 + 1)
        d.append(0x44) // 'D'
        d.append(0x20) // ' '
        if payload.count > 0 {
            payload.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
                guard let base = raw.baseAddress else { return }
                let typed = base.assumingMemoryBound(to: UInt8.self)
                let view = UnsafeBufferPointer<UInt8>(start: typed, count: payload.count)
                LineCodec.escapeForDataLine(view, into: &d)
            }
        }
        d.append(0x0A) // LF
        return d
    }
}

// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// LineCodec.swift — pure value-type encoder/decoder for the Assuan wire
// format used by gpg-agent <-> pinentry. Re-implemented from the spec in
// /Users/rwhitworth/Development/pinentry/pinentry/pinentry.c lines 244–295
// (`copy_and_escape`, `do_unescape_inplace`).
//
// Wire rules:
//   * Bytes < 0x20 (control) and the literal '+' (0x2B) and '%' (0x25) are
//     percent-escaped as %HH (uppercase hex). The C source escapes only
//     `< 0x20` and `+`; we additionally escape `%` itself so that round-trips
//     preserve a literal percent sign — without this, a `%` in plaintext
//     would survive escape unchanged and then be misinterpreted as the start
//     of an escape on decode.
//   * Space (0x20) is encoded as '+'. Decoding maps '+' back to space.
//   * Lines are LF-terminated (0x0A); payload max 1000 bytes (LineCodec
//     enforces this on both encode and decode).

import Foundation
import SecureMemory

// MARK: - LineCodec

public enum LineCodec {

    /// Maximum payload length for a single Assuan line, excluding the trailing LF.
    public static let maxLineLength = 1000

    public enum DecodeError: Error, Equatable {
        case invalidEscape
        case lineTooLong
        case invalidUtf8
    }

    // MARK: Escape

    /// Percent-escape a buffer of raw bytes into an Assuan-safe ASCII string.
    /// Always succeeds; the caller is responsible for ensuring the resulting
    /// string fits within `maxLineLength` if the line will be transmitted.
    public static func escape(_ bytes: UnsafeBufferPointer<UInt8>) -> String {
        // Worst-case expansion: every byte becomes %HH (3 ASCII chars).
        var out = [UInt8]()
        out.reserveCapacity(bytes.count * 3)
        for b in bytes {
            appendEscaped(byte: b, into: &out)
        }
        // All output is ASCII, so UTF-8 decode is infallible.
        return String(decoding: out, as: UTF8.self)
    }

    /// Decode an Assuan-escaped string into its raw byte sequence.
    public static func unescape(_ s: String) throws -> [UInt8] {
        // Reject pre-emptively if the *encoded* form already exceeds the
        // wire-line cap. We don't need to count UTF-8 scalars — Assuan lines
        // are pure ASCII once escaped, so .utf8.count == byte count.
        if s.utf8.count > maxLineLength {
            throw DecodeError.lineTooLong
        }
        var out = [UInt8]()
        out.reserveCapacity(s.utf8.count)
        try decodeBytes(s[...]) { byte in
            out.append(byte)
        }
        return out
    }

    /// Decode an Assuan-escaped substring directly into a `SecureBytes`. This
    /// is the path used for `D`-line passphrase data: the decoded bytes never
    /// touch a `Swift.String` or `Array<UInt8>`.
    public static func unescape(_ s: Substring, into out: SecureBytes) throws {
        if s.utf8.count > maxLineLength {
            throw DecodeError.lineTooLong
        }
        try decodeBytes(s) { byte in
            out.append(byte)
        }
    }

    // MARK: - Internal helpers

    /// Append a single source byte to `out` in its escaped form.
    ///
    /// Upstream `copy_and_escape` only escapes `< 0x20` and `+`, but its
    /// output is `char*`, not Swift's UTF-8-validated `String`. We escape
    /// the same bytes plus '%' (so a literal % round-trips) AND every byte
    /// `>= 0x7F`. The high-byte case is forced on us by Swift: a lone byte
    /// like 0xCF is not valid UTF-8, so passing it through would be replaced
    /// with U+FFFD when the result is materialised as a `String`. Escaping
    /// keeps the output pure ASCII and lossless. Decoders (theirs and ours)
    /// accept `%HH` for any byte value, so this stays wire-compatible.
    private static func appendEscaped(byte b: UInt8, into out: inout [UInt8]) {
        switch b {
        case 0x20: // space -> '+'
            out.append(0x2B)
        case 0x2B, 0x25: // '+' or '%' -> %HH
            appendPercentHex(b, into: &out)
        case 0..<0x20, 0x7F...0xFF: // control / 8-bit -> %HH
            appendPercentHex(b, into: &out)
        default:
            out.append(b)
        }
    }

    private static func appendPercentHex(_ b: UInt8, into out: inout [UInt8]) {
        out.append(0x25) // '%'
        out.append(hexDigit(b >> 4))
        out.append(hexDigit(b & 0x0F))
    }

    private static func hexDigit(_ nibble: UInt8) -> UInt8 {
        // Uppercase hex, matching upstream's `%02X` formatting.
        nibble < 10 ? (0x30 + nibble) : (0x41 + (nibble - 10))
    }

    /// Walk an escaped substring and emit each decoded byte via `sink`.
    /// Decoding rules mirror upstream `do_unescape_inplace`:
    ///   * `%HH` → byte with that hex value (HH must be two hex digits).
    ///   * `+`   → space (0x20).
    ///   * everything else → pass through, treating each UTF-8 code unit as
    ///     a literal byte.
    /// A trailing bare `%` or `%X` (one hex digit) is rejected as invalid.
    private static func decodeBytes(
        _ s: Substring,
        sink: (UInt8) throws -> Void
    ) throws {
        let utf8 = Array(s.utf8)
        var i = 0
        while i < utf8.count {
            let b = utf8[i]
            if b == 0x25 { // '%'
                guard i + 2 < utf8.count else {
                    throw DecodeError.invalidEscape
                }
                guard
                    let hi = hexValue(utf8[i + 1]),
                    let lo = hexValue(utf8[i + 2])
                else {
                    throw DecodeError.invalidEscape
                }
                try sink((hi << 4) | lo)
                i += 3
            } else if b == 0x2B { // '+'
                try sink(0x20)
                i += 1
            } else {
                try sink(b)
                i += 1
            }
        }
    }

    private static func hexValue(_ c: UInt8) -> UInt8? {
        switch c {
        case 0x30...0x39: return c - 0x30
        case 0x41...0x46: return c - 0x41 + 10
        case 0x61...0x66: return c - 0x61 + 10
        default: return nil
        }
    }
}

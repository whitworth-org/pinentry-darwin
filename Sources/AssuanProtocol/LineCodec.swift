// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// LineCodec.swift — pure value-type encoder/decoder for the Assuan wire
// format used by gpg-agent <-> pinentry. Re-implemented from the spec in
// /Users/rwhitworth/Development/pinentry/pinentry/pinentry.c lines 244–295
// (`copy_and_escape`, `do_unescape_inplace`).
//
// Two encoder/decoder pairs, used in different contexts:
//
//   1. Command-argument encoding (`escape` / `unescape`): used for OPTION
//      values, SETDESC/SETPROMPT/etc. arguments, and the INQUIRE QUALITY
//      argument. Space ↔ '+' substitution applies here. Mirrors upstream
//      `copy_and_escape` (pinentry.c:244–268).
//
//   2. Data-line encoding (`escapeForDataLine` / `unescapeFromDataLine`):
//      used for `D` payloads on both directions. Per the Assuan spec
//      (https://www.gnupg.org/documentation/manuals/assuan/, "Data
//      Lines"), data-line payloads percent-escape control bytes and the
//      special characters `%`, `+`, but do NOT substitute `+` for space.
//      This is critical for passphrases containing spaces — our previous
//      symmetric use of the command-arg encoder for `D` lines would have
//      corrupted any space-bearing passphrase on the wire.
//
// Common rules across both:
//   * Bytes < 0x20 (control) and the literal '+' (0x2B) and '%' (0x25) are
//     percent-escaped as %HH (uppercase hex). The C source escapes only
//     `< 0x20` and `+`; we additionally escape `%` itself so that round-trips
//     preserve a literal percent sign.
//   * Bytes ≥ 0x7F are also %HH-escaped: Swift's `String(decoding:as:)`
//     would otherwise replace lone high bytes with U+FFFD, losing data.
//   * Lines are LF-terminated (0x0A); payload max 1000 bytes.

public import Foundation
public import SecureMemory

// MARK: - LineCodec

public enum LineCodec {

    /// Maximum payload length for a single Assuan line, excluding the trailing LF.
    public static let maxLineLength = 1000

    public enum DecodeError: Error, Equatable {
        case invalidEscape
        case lineTooLong
        case invalidUtf8
        /// The `SecureBytes` passed as the decode destination filled up
        /// before the input was exhausted.
        case destinationFull
    }

    // MARK: Escape

    /// Percent-escape a buffer of raw bytes into an Assuan-safe ASCII string.
    /// Always succeeds; the caller is responsible for ensuring the resulting
    /// string fits within `maxLineLength` if the line will be transmitted.
    ///
    /// SECURITY: this convenience materialises the escaped form as a
    /// `Swift.String`, which is regular non-locked, non-zeroed heap. Do
    /// **not** call this with secret bytes — use the `into:` variant
    /// below so the bytes flow directly into the wire-output buffer.
    public static func escape(_ bytes: Span<UInt8>) -> String {
        var out = Data()
        out.reserveCapacity(bytes.count * 3)
        escape(bytes, into: &out)
        return String(decoding: out, as: UTF8.self)
    }

    /// Byte-output variant of `escape`: append the escaped form of
    /// `bytes` directly into `out`. The caller's `out` buffer is the
    /// wire-write target, so no intermediate `Swift.String` ever holds
    /// the escaped bytes. THIS is the variant secret callers must use.
    public static func escape(
        _ bytes: Span<UInt8>,
        into out: inout Data
    ) {
        for i in bytes.indices {
            appendEscaped(byte: bytes[i], into: &out)
        }
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
    /// is used for command-argument decoding into a secure buffer; for
    /// `D`-line payloads use `unescapeFromDataLine(_:into:)` instead, which
    /// skips the `+`↔space substitution.
    ///
    /// - Throws: `DecodeError.destinationFull` if `out` runs out of capacity.
    ///   Bytes decoded before that point stay in `out`; the caller owns
    ///   wiping it.
    public static func unescape(_ s: Substring, into out: SecureBytes) throws {
        if s.utf8.count > maxLineLength {
            throw DecodeError.lineTooLong
        }
        try decodeBytes(s, plusIsSpace: true) { byte in
            try appendChecked(byte, to: out)
        }
    }

    // MARK: Data-line escape (no + ↔ space)

    /// Percent-escape a buffer for transmission on an Assuan `D` line. Differs
    /// from `escape` in that space (0x20) passes through verbatim — the `+`
    /// substitution is a command-argument convention only, not a data-line
    /// rule (Assuan spec, "Data Lines").
    ///
    /// SECURITY: this convenience materialises the escaped form as a
    /// `Swift.String`. For the common case of an ASCII passphrase
    /// containing none of `+`, `%`, control bytes, or high bits, the
    /// escaped form is byte-identical to the plaintext — which means
    /// the returned `String` IS the secret in unwiped, non-locked
    /// Swift heap. Use the `into:` variant below for any secret
    /// payload; the production wire path uses it.
    public static func escapeForDataLine(_ bytes: Span<UInt8>) -> String {
        var out = Data()
        out.reserveCapacity(bytes.count * 3)
        escapeForDataLine(bytes, into: &out)
        return String(decoding: out, as: UTF8.self)
    }

    /// Byte-output variant of `escapeForDataLine`: append the escaped
    /// form of `bytes` directly into `out`. `out` is the caller's
    /// wire-write buffer, so no intermediate `Swift.String` or
    /// unrelated allocation holds the escaped bytes. THIS is the
    /// variant the production `Response.encodeDataLine` uses for
    /// SecureBytes payloads.
    public static func escapeForDataLine(
        _ bytes: Span<UInt8>,
        into out: inout Data
    ) {
        for i in bytes.indices {
            appendEscapedForDataLine(byte: bytes[i], into: &out)
        }
    }

    /// Decode a `D`-line escaped string. Mirrors `escapeForDataLine`: `%HH`
    /// is decoded; `+` is left as a literal `+`; everything else passes
    /// through.
    public static func unescapeFromDataLine(_ s: String) throws -> [UInt8] {
        if s.utf8.count > maxLineLength {
            throw DecodeError.lineTooLong
        }
        var out = [UInt8]()
        out.reserveCapacity(s.utf8.count)
        try decodeBytes(s[...], plusIsSpace: false) { byte in
            out.append(byte)
        }
        return out
    }

    /// Like `unescapeFromDataLine` but routes bytes into a `SecureBytes`
    /// without ever copying through a `Swift.String` or `Array<UInt8>`.
    ///
    /// - Throws: `DecodeError.destinationFull` if `out` runs out of capacity.
    public static func unescapeFromDataLine(_ s: Substring, into out: SecureBytes) throws {
        if s.utf8.count > maxLineLength {
            throw DecodeError.lineTooLong
        }
        try decodeBytes(s, plusIsSpace: false) { byte in
            try appendChecked(byte, to: out)
        }
    }

    // MARK: - Internal helpers

    /// `SecureBytes.append` traps when full, which untrusted input must
    /// never be able to trigger, so decoders check first and throw.
    private static func appendChecked(_ byte: UInt8, to out: SecureBytes) throws {
        guard out.count < out.capacity else {
            throw DecodeError.destinationFull
        }
        out.append(byte)
    }

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
    private static func appendEscaped(byte b: UInt8, into out: inout Data) {
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

    /// Like `appendEscaped` but does NOT remap space → '+'. Used for `D`-line
    /// payloads where the `+` substitution would corrupt space-bearing data.
    private static func appendEscapedForDataLine(byte b: UInt8, into out: inout Data) {
        switch b {
        case 0x2B, 0x25: // '+' or '%' -> %HH
            appendPercentHex(b, into: &out)
        case 0..<0x20, 0x7F...0xFF: // control / 8-bit -> %HH
            appendPercentHex(b, into: &out)
        default: // space and printable bytes pass through
            out.append(b)
        }
    }

    private static func appendPercentHex(_ b: UInt8, into out: inout Data) {
        out.append(0x25) // '%'
        out.append(hexDigit(b >> 4))
        out.append(hexDigit(b & 0x0F))
    }

    private static func hexDigit(_ nibble: UInt8) -> UInt8 {
        // Uppercase hex, matching upstream's `%02X` formatting.
        nibble < 10 ? (0x30 + nibble) : (0x41 + (nibble - 10))
    }

    /// Walk an escaped substring and emit each decoded byte via `sink`.
    ///
    /// Decoding rules:
    ///   * `%HH` → byte with that hex value (HH must be two hex digits).
    ///   * `+`   → space (0x20) when `plusIsSpace` is true (command-argument
    ///             convention); literal `+` (0x2B) when false (D-line rule).
    ///   * everything else → pass through, treating each UTF-8 code unit as
    ///     a literal byte.
    /// A trailing bare `%` or `%X` (one hex digit) is rejected as invalid.
    private static func decodeBytes(
        _ s: Substring,
        plusIsSpace: Bool = true,
        sink: (UInt8) throws -> Void
    ) throws {
        // Walk the UTF-8 view in place: copying it into an `Array` first
        // would leave an unwiped duplicate of any secret-bearing input.
        var iterator = s.utf8.makeIterator()
        while let b = iterator.next() {
            switch b {
            case 0x25: // '%'
                guard
                    let hi = iterator.next().flatMap(hexValue),
                    let lo = iterator.next().flatMap(hexValue)
                else {
                    throw DecodeError.invalidEscape
                }
                try sink((hi << 4) | lo)
            case 0x2B: // '+'
                try sink(plusIsSpace ? 0x20 : 0x2B)
            default:
                try sink(b)
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

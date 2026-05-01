// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// PinentryFuzzLineCodec — exercises the public escape/unescape primitives
// on Sources/AssuanProtocol/LineCodec.swift. Goals:
//
//   * find framing-adjacent bugs: lineTooLong handling, %HH boundary
//     conditions, partial trailing %, partial UTF-8 sequences;
//   * find encode/decode asymmetry: escape -> unescape MUST round-trip
//     for every byte sequence (the existing XCTests cover individual
//     bytes; the fuzzer hunts for combinations);
//   * find decode crashes on adversarial inputs (force-unwraps, OOB
//     reads inside decodeBytes).
//
// Errors are caught and discarded — that is the correct behaviour for a
// parser. Memory errors, fatal errors, and force-unwrap traps WILL crash
// the process and libFuzzer will report a crash artifact.

import Foundation
import Darwin
import AssuanProtocol

/// Bug-discovery sink. We avoid `preconditionFailure` because on macOS
/// arm64 it raises SIGTRAP, which libFuzzer does not catch — no artifact
/// would be written. `abort()` raises SIGABRT, which libFuzzer DOES catch.
@inline(never)
private func reportFuzzBug(_ msg: String) -> Never {
    FileHandle.standardError.write(Data("FUZZ-BUG: \(msg)\n".utf8))
    abort()
}

/// Common entry point shared by both the libFuzzer cdecl shim and the
/// SwiftPM executable wrapper (Fuzz/.../main.swift).
@inline(never)
public func fuzzLineCodecOnce(_ bytes: [UInt8]) {
    if bytes.isEmpty { return }

    // Decide one of three modes from the first byte: command-arg unescape,
    // data-line unescape, or escape-then-unescape round-trip. Spreading the
    // budget across modes lets one corpus drive coverage of all three
    // public surfaces.
    let mode = bytes[0] & 0x03
    let payload = Array(bytes.dropFirst())

    switch mode {
    case 0:
        // Command-arg unescape from a String. We deliberately accept any
        // byte sequence; if it isn't UTF-8 we skip (matches how the line
        // reader rejects non-UTF-8 lines upstream).
        if let s = String(bytes: payload, encoding: .utf8) {
            _ = try? LineCodec.unescape(s)
        }

    case 1:
        // Data-line unescape from a String.
        if let s = String(bytes: payload, encoding: .utf8) {
            _ = try? LineCodec.unescapeFromDataLine(s)
        }

    case 2:
        // Round-trip: escape arbitrary bytes, then unescape. The decoded
        // bytes MUST equal the input. A divergence is a real bug.
        let escaped = payload.withUnsafeBufferPointer { LineCodec.escape($0) }
        if let decoded = try? LineCodec.unescape(escaped), decoded != payload {
            // Asymmetric round-trip is a wire-format bug.
            reportFuzzBug("LineCodec round-trip mismatch (cmd-arg path, payload bytes=\(payload.count))")
        }

    default:
        // Round-trip via escapeForDataLine.
        let escaped = payload.withUnsafeBufferPointer { LineCodec.escapeForDataLine($0) }
        if let decoded = try? LineCodec.unescapeFromDataLine(escaped), decoded != payload {
            reportFuzzBug("LineCodec round-trip mismatch (data-line path, payload bytes=\(payload.count))")
        }
    }
}

/// libFuzzer entry point. Returns 0 to keep fuzzing; any crash inside
/// `fuzzLineCodecOnce` propagates as a deadly signal which libFuzzer
/// catches and writes as an artifact.
@_cdecl("LLVMFuzzerTestOneInput")
public func LLVMFuzzerTestOneInput_LineCodec(
    _ data: UnsafePointer<UInt8>,
    _ size: Int
) -> CInt {
    let buf = UnsafeBufferPointer(start: data, count: size)
    fuzzLineCodecOnce(Array(buf))
    return 0
}

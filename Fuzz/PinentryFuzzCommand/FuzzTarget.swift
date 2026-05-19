// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// PinentryFuzzCommand — fuzzes Sources/AssuanProtocol/Command.swift
// `Command.parse(_:)`. Goals:
//
//   * verb dispatch crashes (uppercased ASCII assumption breaking on
//     non-ASCII verb bytes);
//   * arg-parsing crashes inside the percent-decode chain (already
//     covered by the LineCodec target, but the SETKEYINFO/SETTIMEOUT/
//     OPTION sub-parsers do their own structural parsing);
//   * `parseUserIdFromDescription` corner cases — quoted-pair scanning
//     across multi-byte UTF-8 boundaries.
//
// Bytes are best-effort decoded as UTF-8; non-UTF-8 input is skipped.
// Real Assuan lines are pure ASCII once on the wire, but we still throw
// non-ASCII at the parser to make sure trimmingCharacters / firstIndex
// don't panic on grapheme-cluster oddities.

import Foundation
import AssuanProtocol

@inline(never)
public func fuzzCommandOnce(_ bytes: [UInt8]) {
    if bytes.isEmpty { return }
    guard let line = String(bytes: bytes, encoding: .utf8) else { return }

    // Strip any embedded LF/CR — the wire layer would have done this
    // before handing the line to the parser, and feeding raw newlines
    // here just measures the test harness, not the parser.
    let cleaned = line.replacingOccurrences(of: "\n", with: "")
                      .replacingOccurrences(of: "\r", with: "")

    _ = try? Command.parse(cleaned)

    // Also exercise the public helper that runs over SETDESC text. It
    // never throws — we just look for crashes on adversarial quote
    // patterns and oversized inputs.
    _ = Command.parseUserIdFromDescription(cleaned)

    // And the fingerprint validator — pure-string over arbitrary input.
    _ = Command.isValidFingerprint(cleaned)

    // Mnemonic sanitisers run on attacker-shaped labels and body text.
    // We look for crashes on adversarial grapheme-cluster shapes and on
    // BOM-only / surrogate-like inputs, not for specific outputs.
    _ = Mnemonic.strip(cleaned)
    _ = Mnemonic.sanitiseBody(cleaned)
}

@_cdecl("LLVMFuzzerTestOneInput")
public func LLVMFuzzerTestOneInput_Command(
    _ data: UnsafePointer<UInt8>,
    _ size: Int
) -> CInt {
    let buf = UnsafeBufferPointer(start: data, count: size)
    fuzzCommandOnce(Array(buf))
    return 0
}

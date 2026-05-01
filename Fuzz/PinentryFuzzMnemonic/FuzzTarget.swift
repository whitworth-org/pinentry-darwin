// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// PinentryFuzzMnemonic — fuzzes Sources/AssuanProtocol/Mnemonic.swift
// `Mnemonic.strip(_:)`. This module is the freshest Assuan-protocol code
// (added with the GTK accelerator strip), so it has the highest
// per-LOC defect probability; underscore-walking with String.Index is a
// known footgun zone (grapheme cluster boundaries, dangling underscores
// at end-of-string, multi-byte underscore look-alikes from Cyrillic /
// Cherokee scripts).
//
// Properties to crash on:
//   * any String.Index advance past endIndex (would trap);
//   * `s[next]` when next == endIndex (would trap);
//   * mismatch between s.count (Character count) and the per-byte
//     reservation (would not crash, but wastes capacity — not our
//     concern here, we hunt traps);
//   * the convenience stripOptional path on nil and on empty strings.

import Foundation
import Darwin
import AssuanProtocol

/// Bug-discovery sink — see PinentryFuzzLineCodec for rationale.
@inline(never)
private func reportFuzzBug(_ msg: String) -> Never {
    FileHandle.standardError.write(Data("FUZZ-BUG: \(msg)\n".utf8))
    abort()
}

@inline(never)
public func fuzzMnemonicOnce(_ bytes: [UInt8]) {
    guard let s = String(bytes: bytes, encoding: .utf8) else { return }

    // Primary: the actual strip routine.
    _ = Mnemonic.strip(s)

    // Optional wrapper, both nil and value paths.
    _ = Mnemonic.stripOptional(nil)
    _ = Mnemonic.stripOptional(s)

    // Property check: idempotence is NOT guaranteed (e.g. "__" -> "_"
    // -> "" — the second strip removes the now-dangling underscore). So
    // we don't assert it. We DO assert one weaker property: stripping
    // a string that contains no underscores must return the original
    // verbatim.
    if !s.contains("_") {
        let stripped = Mnemonic.strip(s)
        if stripped != s {
            reportFuzzBug("Mnemonic.strip altered an underscore-free string of length \(s.count)")
        }
    }
}

@_cdecl("LLVMFuzzerTestOneInput")
public func LLVMFuzzerTestOneInput_Mnemonic(
    _ data: UnsafePointer<UInt8>,
    _ size: Int
) -> CInt {
    let buf = UnsafeBufferPointer(start: data, count: size)
    fuzzMnemonicOnce(Array(buf))
    return 0
}

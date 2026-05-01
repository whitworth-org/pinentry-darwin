// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// PinentryFuzzResponse — fuzzes Sources/AssuanProtocol/Response.swift's
// `D`-line escape via `Response.data(SecureBytes(_:)).wirePayloads()`.
// Goals:
//
//   * encoder/decoder symmetry: every encoded D-line MUST round-trip
//     through `LineCodec.unescapeFromDataLine` to the exact input bytes
//     (concatenated across continuation lines per Assuan spec — FZ-1
//     fix);
//   * length expansion bug surface: 3x worst-case escape, plus the
//     "D " prefix + LF suffix — make sure no buffer underflow;
//   * SecureBytes interactions: feeding right at SecureBytes.maxLength
//     (16 KiB) is the obvious cliff. Above the cap, SecureBytes will
//     silently truncate via its own append rules — we accept that
//     and only assert round-trip on the bytes the buffer accepted;
//   * line-length invariant: every emitted wire line MUST be ≤
//     `LineCodec.maxLineLength` + 1 (LF). The pre-FZ-1 encoder
//     violated this for ≥334 high-bit / control bytes, which the
//     same library's decoder rejected (`lineTooLong`).
//
// We bound input size at 8 KiB to keep individual iterations fast and
// avoid the 16 KiB SecureBytes ceiling fight.

import Foundation
import Darwin
import AssuanProtocol
import SecureMemory

/// Bug-discovery sink. We deliberately AVOID Swift's `preconditionFailure`
/// because on macOS arm64 it calls `__builtin_trap` (SIGTRAP), which
/// libFuzzer's installed signal handlers do NOT catch — the process dies
/// without an artifact being written. `abort()` raises SIGABRT, which
/// libFuzzer DOES catch, so we get the crashing input written to
/// `findings/crash-<sha1>` for replay.
@inline(never)
private func reportFuzzBug(_ msg: String) -> Never {
    FileHandle.standardError.write(Data("FUZZ-BUG: \(msg)\n".utf8))
    abort()
}

/// Extract the escaped portion of a single `D <escaped>\n` payload as
/// a Swift String suitable for the decoder. Returns nil only if the
/// wire bytes are not valid ASCII/UTF-8 (which would itself be a bug
/// in the encoder).
private func extractEscapedPortion(_ wire: Data, who: String) -> String {
    if wire.count < 3 { reportFuzzBug("\(who): wire line shorter than minimal D prefix") }
    if wire[wire.startIndex] != 0x44 { reportFuzzBug("\(who): missing 'D'") }
    if wire[wire.index(after: wire.startIndex)] != 0x20 { reportFuzzBug("\(who): missing space after D") }
    if wire[wire.index(before: wire.endIndex)] != 0x0A { reportFuzzBug("\(who): missing trailing LF") }
    // FZ-1 invariant: each emitted line stays under the wire-line cap
    // (1000 excluding LF, so 1001 total). Violating this is the bug
    // the original fuzz finding caught.
    let lfInclusive = LineCodec.maxLineLength + 1
    if wire.count > lfInclusive {
        reportFuzzBug("\(who): emitted line \(wire.count) bytes exceeds maxLineLength+1 (\(lfInclusive))")
    }
    let escStart: Data.Index = wire.index(wire.startIndex, offsetBy: 2)
    let escEnd: Data.Index = wire.index(before: wire.endIndex)
    let slice: Data = wire.subdata(in: escStart..<escEnd)
    guard let escaped = String(bytes: slice, encoding: .utf8) else {
        reportFuzzBug("\(who): escaped form not valid ASCII/UTF-8")
    }
    return escaped
}

@inline(never)
public func fuzzResponseOnce(_ bytes: [UInt8]) {
    if bytes.isEmpty { return }

    // Cap to keep iteration fast and stay well below SecureBytes.maxLength.
    let payload = bytes.count > 8192 ? Array(bytes.prefix(8192)) : bytes

    // Path 1: secret D line via SecureBytes. FZ-1 fix: large payloads
    // emit as multiple `D` continuation lines whose concatenated
    // decoded bytes equal the input.
    let secure = SecureBytes(payload)
    let payloads = Response.data(secure).wirePayloads()
    if payloads.isEmpty { reportFuzzBug("Response.data must produce at least one wire line") }

    var concatenated: [UInt8] = []
    for (i, p) in payloads.enumerated() {
        // Each secret payload must be a SecureBytes-backed line.
        guard case .secret(let line) = p else {
            reportFuzzBug("Response.data wire payload \(i) is not a SecureBytes (.secret)")
        }
        let wire = line.withUnsafeBytes { Data($0) }
        let escaped = extractEscapedPortion(wire, who: "secret line \(i)")
        do {
            let decoded = try LineCodec.unescapeFromDataLine(escaped)
            concatenated.append(contentsOf: decoded)
        } catch {
            reportFuzzBug("decode threw on encoder output (line \(i)): \(error) (payload bytes=\(payload.count))")
        }
    }
    if concatenated != payload {
        reportFuzzBug("Response D-line round-trip mismatch (payload bytes=\(payload.count), got=\(concatenated.count))")
    }

    // Path 2: non-secret D line via Data — same invariants.
    let plainPayloads = Response.dataPlaintext(Data(payload)).wirePayloads()
    if plainPayloads.isEmpty { reportFuzzBug("Response.dataPlaintext must produce at least one wire line") }
    var plainConcat: [UInt8] = []
    for (i, p) in plainPayloads.enumerated() {
        guard case .plain(let wire) = p else {
            reportFuzzBug("Response.dataPlaintext wire payload \(i) is not .plain")
        }
        let escaped = extractEscapedPortion(wire, who: "plain line \(i)")
        do {
            let decoded = try LineCodec.unescapeFromDataLine(escaped)
            plainConcat.append(contentsOf: decoded)
        } catch {
            reportFuzzBug("plaintext decode threw on encoder output (line \(i)): \(error)")
        }
    }
    if plainConcat != payload {
        reportFuzzBug("Response plaintext D-line round-trip mismatch")
    }
}

@_cdecl("LLVMFuzzerTestOneInput")
public func LLVMFuzzerTestOneInput_Response(
    _ data: UnsafePointer<UInt8>,
    _ size: Int
) -> CInt {
    let buf = UnsafeBufferPointer(start: data, count: size)
    fuzzResponseOnce(Array(buf))
    return 0
}

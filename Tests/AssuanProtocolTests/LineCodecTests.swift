// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// LineCodecTests — golden vectors and exhaustive byte-range round-trip
// for the Assuan percent-escape / unescape routines.

import Foundation
import SecureMemory
import XCTest
@testable import AssuanProtocol

// MARK: - LineCodecTests

final class LineCodecTests: XCTestCase {

    // MARK: Round-trip

    func testAllByteValuesRoundTrip() throws {
        // Every individual byte 0x00..0xFF must survive escape -> unescape.
        for v in 0...255 {
            let original: [UInt8] = [UInt8(v)]
            let escaped = LineCodec.escape(original.span)
            let decoded = try LineCodec.unescape(escaped)
            XCTAssertEqual(decoded, original, "byte 0x\(String(v, radix: 16)) failed round-trip")
        }
    }

    func testAllBytesAtOnceRoundTrip() throws {
        // The entire 256-byte alphabet in a single buffer.
        let original: [UInt8] = (0...255).map { UInt8($0) }
        let escaped = LineCodec.escape(original.span)
        let decoded = try LineCodec.unescape(escaped)
        XCTAssertEqual(decoded, original)
    }

    // MARK: Golden vectors

    func testGoldenSpaceToPlus() throws {
        let bytes = Array("hello world".utf8)
        let escaped = LineCodec.escape(bytes.span)
        XCTAssertEqual(escaped, "hello+world")
        XCTAssertEqual(try LineCodec.unescape("hello+world"), bytes)
    }

    func testGoldenLiteralPercent() throws {
        let bytes = Array("a%b".utf8)
        let escaped = LineCodec.escape(bytes.span)
        XCTAssertEqual(escaped, "a%25b")
        XCTAssertEqual(try LineCodec.unescape("a%25b"), bytes)
    }

    func testGoldenLiteralPlus() throws {
        let bytes = Array("a+b".utf8)
        let escaped = LineCodec.escape(bytes.span)
        XCTAssertEqual(escaped, "a%2Bb")
        XCTAssertEqual(try LineCodec.unescape("a%2Bb"), bytes)
    }

    func testGoldenNewline() throws {
        let bytes: [UInt8] = [0x0A]
        let escaped = LineCodec.escape(bytes.span)
        XCTAssertEqual(escaped, "%0A")
        XCTAssertEqual(try LineCodec.unescape("%0A"), bytes)
    }

    func testGoldenTab() throws {
        let bytes: [UInt8] = [0x09]
        let escaped = LineCodec.escape(bytes.span)
        XCTAssertEqual(escaped, "%09")
        XCTAssertEqual(try LineCodec.unescape("%09"), bytes)
    }

    // MARK: Decode errors

    func testRejectBarePercentAtEnd() {
        XCTAssertThrowsError(try LineCodec.unescape("abc%")) { err in
            XCTAssertEqual(err as? LineCodec.DecodeError, .invalidEscape)
        }
        XCTAssertThrowsError(try LineCodec.unescape("abc%A")) { err in
            XCTAssertEqual(err as? LineCodec.DecodeError, .invalidEscape)
        }
    }

    func testRejectNonHexAfterPercent() {
        XCTAssertThrowsError(try LineCodec.unescape("a%ZZb")) { err in
            XCTAssertEqual(err as? LineCodec.DecodeError, .invalidEscape)
        }
        XCTAssertThrowsError(try LineCodec.unescape("a%G1b")) { err in
            XCTAssertEqual(err as? LineCodec.DecodeError, .invalidEscape)
        }
    }

    // MARK: Length cap

    func testRejectLineTooLong() {
        // Exactly maxLineLength is OK; one byte over is not.
        let okPayload = String(repeating: "x", count: LineCodec.maxLineLength)
        XCTAssertNoThrow(try LineCodec.unescape(okPayload))

        let tooLong = String(repeating: "x", count: LineCodec.maxLineLength + 1)
        XCTAssertThrowsError(try LineCodec.unescape(tooLong)) { err in
            XCTAssertEqual(err as? LineCodec.DecodeError, .lineTooLong)
        }
    }

    // MARK: Lowercase hex

    func testLowercaseHexDecodesToo() throws {
        // Encoder always produces uppercase, but the decoder should accept
        // either case so we tolerate any peer that emits lowercase.
        XCTAssertEqual(try LineCodec.unescape("%0a"), [0x0A])
        XCTAssertEqual(try LineCodec.unescape("%2b"), [0x2B])
    }

    // MARK: SecureBytes path

    func testUnescapeIntoSecureBytes() throws {
        let secure = SecureBytes(capacity: 64)
        let input: Substring = "hello+world%21"[...]
        try LineCodec.unescape(input, into: secure)
        XCTAssertEqual(contents(of: secure), Array("hello world!".utf8))
    }

    func testUnescapeFromDataLineIntoSecureBytesKeepsPlus() throws {
        let secure = SecureBytes(capacity: 64)
        try LineCodec.unescapeFromDataLine("a+b%20c"[...], into: secure)
        XCTAssertEqual(contents(of: secure), Array("a+b c".utf8))
    }

    /// A hostile peer controls the escaped input, so a destination that is
    /// too small must produce an error, not `SecureBytes`'s overflow trap.
    func testUnescapeIntoTooSmallSecureBytesThrowsInsteadOfTrapping() {
        let small = SecureBytes(capacity: 4)
        XCTAssertThrowsError(try LineCodec.unescape("abcdefgh"[...], into: small)) { err in
            XCTAssertEqual(err as? LineCodec.DecodeError, .destinationFull)
        }
        XCTAssertEqual(small.count, 4, "bytes decoded before the overflow stay in place")

        let smallData = SecureBytes(capacity: 2)
        XCTAssertThrowsError(
            try LineCodec.unescapeFromDataLine("%41%42%43"[...], into: smallData)
        ) { err in
            XCTAssertEqual(err as? LineCodec.DecodeError, .destinationFull)
        }
    }

    func testUnescapeIntoSecureBytesAcceptsExactFit() throws {
        let exact = SecureBytes(capacity: 3)
        try LineCodec.unescape("%41%42%43"[...], into: exact)
        XCTAssertEqual(contents(of: exact), [0x41, 0x42, 0x43])
    }

    private func contents(of secure: SecureBytes) -> [UInt8] {
        secure.withSpan { span in (0..<span.count).map { span[$0] } }
    }

    // MARK: Data-line encoding (no '+' ↔ space)

    // Per the Assuan spec, `D` payloads percent-escape control / `%` / `+`
    // but pass spaces through verbatim. The command-argument convention
    // (space → '+') would corrupt any space-bearing passphrase.
    func testDataLineSpacePassesThrough() {
        let bytes = Array("hello world".utf8)
        let escaped = LineCodec.escapeForDataLine(bytes.span)
        XCTAssertEqual(escaped, "hello world")
    }

    func testDataLinePlusEscaped() {
        let bytes = Array("a+b".utf8)
        let escaped = LineCodec.escapeForDataLine(bytes.span)
        XCTAssertEqual(escaped, "a%2Bb",
                       "literal '+' must be %HH-escaped on D lines so a peer using either decoder reads it back as '+'")
    }

    func testDataLinePercentEscaped() {
        let bytes = Array("100%".utf8)
        let escaped = LineCodec.escapeForDataLine(bytes.span)
        XCTAssertEqual(escaped, "100%25")
    }

    func testDataLineControlBytesEscaped() {
        let bytes: [UInt8] = [0x09, 0x0A, 0x0D, 0x1F]
        let escaped = LineCodec.escapeForDataLine(bytes.span)
        XCTAssertEqual(escaped, "%09%0A%0D%1F")
    }

    func testDataLineRoundTripWithSpaces() throws {
        let original = Array("password with multiple spaces".utf8)
        let escaped = LineCodec.escapeForDataLine(original.span)
        XCTAssertEqual(escaped, "password with multiple spaces")
        let decoded = try LineCodec.unescapeFromDataLine(escaped)
        XCTAssertEqual(decoded, original)
    }

    func testDataLineDecoderTreatsPlusAsLiteral() throws {
        // On a D line, a literal '+' must NOT be decoded to space — that's
        // the command-arg behaviour. The encoder %2B-escapes literal '+',
        // so a bare '+' in a `D` payload from a peer must round-trip as '+'.
        let decoded = try LineCodec.unescapeFromDataLine("a+b")
        XCTAssertEqual(decoded, Array("a+b".utf8))
    }

    func testDataLineAllByteValuesRoundTrip() throws {
        for v in 0...255 {
            let original: [UInt8] = [UInt8(v)]
            let escaped = LineCodec.escapeForDataLine(original.span)
            let decoded = try LineCodec.unescapeFromDataLine(escaped)
            XCTAssertEqual(decoded, original, "byte 0x\(String(v, radix: 16)) failed D-line round-trip")
        }
    }

    // MARK: Byte-output (no Swift.String materialisation)

    // Production callers (Response.encodeDataLine, Session.inquireQuality)
    // route through escape(_:into:) and escapeForDataLine(_:into:) so the
    // escaped bytes never live in unwiped Swift.String storage. The test
    // here pins those byte-output variants so a future regression that
    // accidentally drops them shows up immediately.

    func testEscapeIntoDataMatchesStringForm() {
        let bytes = Array("hello world+%\u{0009}".utf8)
        var out = Data()
        LineCodec.escape(bytes.span, into: &out)
        let asString = String(decoding: out, as: UTF8.self)
        let stringForm = LineCodec.escape(bytes.span)
        XCTAssertEqual(asString, stringForm,
                       "byte-output and String-output variants must produce identical bytes")
    }

    func testEscapeForDataLineIntoDataMatchesStringForm() {
        let bytes = Array("password with + and % and \u{0007}".utf8)
        var out = Data()
        LineCodec.escapeForDataLine(bytes.span, into: &out)
        let asString = String(decoding: out, as: UTF8.self)
        let stringForm = LineCodec.escapeForDataLine(bytes.span)
        XCTAssertEqual(asString, stringForm)
    }

    func testEscapeIntoDataAppendsToExistingPrefix() {
        // Production callers pre-fill the wire prefix ("D ", "INQUIRE
        // QUALITY ") before calling the escape function. Confirm the
        // byte-output escaper appends rather than replacing.
        var out = Data()
        out.append(contentsOf: "D ".utf8)
        let bytes = Array("hi".utf8)
        LineCodec.escapeForDataLine(bytes.span, into: &out)
        out.append(0x0A)
        XCTAssertEqual(String(decoding: out, as: UTF8.self), "D hi\n")
    }

    func testEscapeIntoDataAllByteValuesRoundTrip() throws {
        // Spot-check the byte-output path against the every-byte invariant
        // so a regression in the inner appendEscaped(into: Data) helper is
        // caught even if the String-returning convenience drifts away.
        for v in 0...255 {
            let original: [UInt8] = [UInt8(v)]
            var out = Data()
            LineCodec.escapeForDataLine(original.span, into: &out)
            let decoded = try LineCodec.unescapeFromDataLine(String(decoding: out, as: UTF8.self))
            XCTAssertEqual(decoded, original, "byte 0x\(String(v, radix: 16)) failed byte-output round-trip")
        }
    }
}

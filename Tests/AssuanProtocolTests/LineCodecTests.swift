// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// LineCodecTests — golden vectors and exhaustive byte-range round-trip
// for the Assuan percent-escape / unescape routines.

import XCTest
@testable import AssuanProtocol
import SecureMemory

// MARK: - LineCodecTests

final class LineCodecTests: XCTestCase {

    // MARK: Round-trip

    func testAllByteValuesRoundTrip() throws {
        // Every individual byte 0x00..0xFF must survive escape -> unescape.
        for v in 0...255 {
            let original: [UInt8] = [UInt8(v)]
            let escaped = original.withUnsafeBufferPointer { LineCodec.escape($0) }
            let decoded = try LineCodec.unescape(escaped)
            XCTAssertEqual(decoded, original, "byte 0x\(String(v, radix: 16)) failed round-trip")
        }
    }

    func testAllBytesAtOnceRoundTrip() throws {
        // The entire 256-byte alphabet in a single buffer.
        let original: [UInt8] = (0...255).map { UInt8($0) }
        let escaped = original.withUnsafeBufferPointer { LineCodec.escape($0) }
        let decoded = try LineCodec.unescape(escaped)
        XCTAssertEqual(decoded, original)
    }

    // MARK: Golden vectors

    func testGoldenSpaceToPlus() throws {
        let bytes = Array("hello world".utf8)
        let escaped = bytes.withUnsafeBufferPointer { LineCodec.escape($0) }
        XCTAssertEqual(escaped, "hello+world")
        XCTAssertEqual(try LineCodec.unescape("hello+world"), bytes)
    }

    func testGoldenLiteralPercent() throws {
        let bytes = Array("a%b".utf8)
        let escaped = bytes.withUnsafeBufferPointer { LineCodec.escape($0) }
        XCTAssertEqual(escaped, "a%25b")
        XCTAssertEqual(try LineCodec.unescape("a%25b"), bytes)
    }

    func testGoldenLiteralPlus() throws {
        let bytes = Array("a+b".utf8)
        let escaped = bytes.withUnsafeBufferPointer { LineCodec.escape($0) }
        XCTAssertEqual(escaped, "a%2Bb")
        XCTAssertEqual(try LineCodec.unescape("a%2Bb"), bytes)
    }

    func testGoldenNewline() throws {
        let bytes: [UInt8] = [0x0A]
        let escaped = bytes.withUnsafeBufferPointer { LineCodec.escape($0) }
        XCTAssertEqual(escaped, "%0A")
        XCTAssertEqual(try LineCodec.unescape("%0A"), bytes)
    }

    func testGoldenTab() throws {
        let bytes: [UInt8] = [0x09]
        let escaped = bytes.withUnsafeBufferPointer { LineCodec.escape($0) }
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
        secure.withUnsafeBytes { buf in
            XCTAssertEqual(Array(buf), Array("hello world!".utf8))
        }
    }

    // MARK: Data-line encoding (no '+' ↔ space)

    // Per the Assuan spec, `D` payloads percent-escape control / `%` / `+`
    // but pass spaces through verbatim. The command-argument convention
    // (space → '+') would corrupt any space-bearing passphrase.
    func testDataLineSpacePassesThrough() {
        let bytes = Array("hello world".utf8)
        let escaped = bytes.withUnsafeBufferPointer { LineCodec.escapeForDataLine($0) }
        XCTAssertEqual(escaped, "hello world")
    }

    func testDataLinePlusEscaped() {
        let bytes = Array("a+b".utf8)
        let escaped = bytes.withUnsafeBufferPointer { LineCodec.escapeForDataLine($0) }
        XCTAssertEqual(escaped, "a%2Bb",
                       "literal '+' must be %HH-escaped on D lines so a peer using either decoder reads it back as '+'")
    }

    func testDataLinePercentEscaped() {
        let bytes = Array("100%".utf8)
        let escaped = bytes.withUnsafeBufferPointer { LineCodec.escapeForDataLine($0) }
        XCTAssertEqual(escaped, "100%25")
    }

    func testDataLineControlBytesEscaped() {
        let bytes: [UInt8] = [0x09, 0x0A, 0x0D, 0x1F]
        let escaped = bytes.withUnsafeBufferPointer { LineCodec.escapeForDataLine($0) }
        XCTAssertEqual(escaped, "%09%0A%0D%1F")
    }

    func testDataLineRoundTripWithSpaces() throws {
        let original = Array("password with multiple spaces".utf8)
        let escaped = original.withUnsafeBufferPointer { LineCodec.escapeForDataLine($0) }
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
            let escaped = original.withUnsafeBufferPointer { LineCodec.escapeForDataLine($0) }
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
        bytes.withUnsafeBufferPointer { LineCodec.escape($0, into: &out) }
        let asString = String(decoding: out, as: UTF8.self)
        let stringForm = bytes.withUnsafeBufferPointer { LineCodec.escape($0) }
        XCTAssertEqual(asString, stringForm,
                       "byte-output and String-output variants must produce identical bytes")
    }

    func testEscapeForDataLineIntoDataMatchesStringForm() {
        let bytes = Array("password with + and % and \u{0007}".utf8)
        var out = Data()
        bytes.withUnsafeBufferPointer { LineCodec.escapeForDataLine($0, into: &out) }
        let asString = String(decoding: out, as: UTF8.self)
        let stringForm = bytes.withUnsafeBufferPointer { LineCodec.escapeForDataLine($0) }
        XCTAssertEqual(asString, stringForm)
    }

    func testEscapeIntoDataAppendsToExistingPrefix() {
        // Production callers pre-fill the wire prefix ("D ", "INQUIRE
        // QUALITY ") before calling the escape function. Confirm the
        // byte-output escaper appends rather than replacing.
        var out = Data()
        out.append(contentsOf: "D ".utf8)
        let bytes = Array("hi".utf8)
        bytes.withUnsafeBufferPointer { LineCodec.escapeForDataLine($0, into: &out) }
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
            original.withUnsafeBufferPointer { LineCodec.escapeForDataLine($0, into: &out) }
            let decoded = try LineCodec.unescapeFromDataLine(String(decoding: out, as: UTF8.self))
            XCTAssertEqual(decoded, original, "byte 0x\(String(v, radix: 16)) failed byte-output round-trip")
        }
    }
}

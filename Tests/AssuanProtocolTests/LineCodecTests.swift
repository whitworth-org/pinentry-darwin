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
}

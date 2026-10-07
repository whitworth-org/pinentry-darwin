// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// ResponseTests — wire-encoding of non-secret reply lines. Focused on the
// AS-3 CRLF-injection backstop in `Response.lineData`.

import Foundation
import SecureMemory
import XCTest
@testable import AssuanProtocol

// MARK: - ResponseTests

final class ResponseTests: XCTestCase {

    /// Decode a `.plain` WirePayload back into a String for assertion.
    private func plainLine(_ payload: WirePayload) -> String {
        switch payload {
        case .plain(let data):
            return String(data: data, encoding: .utf8) ?? "<non-utf8>"
        case .secret:
            return "<secret>"
        }
    }

    // MARK: - AS-3: forbidden bytes are dropped, never abort the process

    func testLineDataDropsCRLFInjection() throws {
        // A body carrying CR/LF must NOT abort (pre-AS-3 this was a
        // `precondition`, an attacker-triggerable process abort if any
        // future refactor routed attacker text here) and must NOT emit the
        // CR/LF onto the wire (which would forge a second response line).
        let response = Response.okWithComment("OK\r\nERR 1 forged")
        let payloads = response.wirePayloads()

        // Exactly one wire line — the injected LF did not split it in two.
        XCTAssertEqual(payloads.count, 1)

        let line = plainLine(payloads[0])
        // The encoded bytes carry exactly one trailing LF (the framing one).
        XCTAssertEqual(line.utf8.filter { $0 == 0x0A }.count, 1)
        // No CR survived.
        XCTAssertFalse(line.utf8.contains(0x0D))
        // The forbidden bytes are stripped, so "OK\r\nERR..." collapses to
        // "OKERR 1 forged" appended after the "OK " prefix.
        XCTAssertEqual(line, "OK OKERR 1 forged\n")
    }

    func testLineDataDropsNulAndDel() throws {
        let response = Response.okWithComment("a\u{00}b\u{7F}c")
        let line = plainLine(response.wirePayloads()[0])
        XCTAssertFalse(line.utf8.contains(0x00))
        XCTAssertFalse(line.utf8.contains(0x7F))
        XCTAssertEqual(line, "OK abc\n")
    }

    func testLineDataCleanBodyUnchanged() throws {
        // The common case: a clean comment round-trips verbatim.
        let line = plainLine(Response.okWithComment("Pleased to meet you").wirePayloads()[0])
        XCTAssertEqual(line, "OK Pleased to meet you\n")
    }

    // MARK: - Data-line chunking and escaping

    /// Wire bytes of every payload, whether plain or secret.
    private func wireBytes(_ payload: WirePayload) -> [UInt8] {
        switch payload {
        case .plain(let data):
            return Array(data)
        case .secret(let secure):
            return secure.withSpan { span in (0..<span.count).map { span[$0] } }
        }
    }

    /// Strip `D ` and LF from each line and unescape the remainder, which is
    /// what the receiving agent does before concatenating continuation lines.
    private func reassemble(_ payloads: [WirePayload]) throws -> [UInt8] {
        try payloads.flatMap { payload -> [UInt8] in
            let wire = wireBytes(payload)
            XCTAssertEqual(Array(wire.prefix(2)), Array("D ".utf8))
            XCTAssertEqual(wire.last, 0x0A)
            XCTAssertLessThanOrEqual(wire.count - 1, LineCodec.maxLineLength)
            let body = String(decoding: wire.dropFirst(2).dropLast(), as: UTF8.self)
            return try LineCodec.unescapeFromDataLine(body)
        }
    }

    func testSecretDataSplitsAndRoundTripsEveryByteValue() throws {
        let source = (0..<1500).map { UInt8($0 % 256) }
        let payloads = Response.data(SecureBytes(source)).wirePayloads()
        XCTAssertEqual(payloads.count, 5, "1500 bytes at 332 per line is five lines")
        for payload in payloads {
            guard case .secret = payload else { return XCTFail("secret data must stay secret") }
        }
        XCTAssertEqual(try reassemble(payloads), source)
    }

    func testPlaintextDataSplitsAndRoundTripsEveryByteValue() throws {
        let source = (0..<1500).map { UInt8($0 % 256) }
        let payloads = Response.dataPlaintext(Data(source)).wirePayloads()
        XCTAssertEqual(payloads.count, 5)
        for payload in payloads {
            guard case .plain = payload else { return XCTFail("plaintext data must stay plain") }
        }
        XCTAssertEqual(try reassemble(payloads), source)
    }

    func testDataExactlyAtChunkBoundaryHasNoEmptyTrailingLine() {
        let atBoundary = Array(repeating: UInt8(0x61), count: Response.maxSourceBytesPerDataLine)
        XCTAssertEqual(Response.data(SecureBytes(atBoundary)).wirePayloads().count, 1)
        XCTAssertEqual(Response.dataPlaintext(Data(atBoundary)).wirePayloads().count, 1)
        let over = atBoundary + [0x61]
        XCTAssertEqual(Response.data(SecureBytes(over)).wirePayloads().count, 2)
        XCTAssertEqual(Response.dataPlaintext(Data(over)).wirePayloads().count, 2)
    }

    func testEmptyDataEncodesAsEmptyDataLine() {
        let secret = Response.data(SecureBytes(capacity: 4)).wirePayloads()
        XCTAssertEqual(secret.map(wireBytes), [Array("D \n".utf8)])
        let plain = Response.dataPlaintext(Data()).wirePayloads()
        XCTAssertEqual(plain.map(wireBytes), [Array("D \n".utf8)])
    }

    func testSecretDataLineKeepsSpaceAndEscapesPlusPercentControlAndHighBytes() {
        let source: [UInt8] = [0x20, 0x2B, 0x25, 0x0A, 0x7F, 0xFF, 0x41]
        let wire = Response.data(SecureBytes(source)).wirePayloads().map(wireBytes)
        XCTAssertEqual(wire, [Array("D  %2B%25%0A%7F%FFA\n".utf8)])
    }
}

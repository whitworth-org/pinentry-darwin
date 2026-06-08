// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// ResponseTests — wire-encoding of non-secret reply lines. Focused on the
// AS-3 CRLF-injection backstop in `Response.lineData`.

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
}

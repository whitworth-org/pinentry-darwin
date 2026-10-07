// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// SessionTests — exercise the Session actor against a pair of `Pipe`
// instances so the test process plays the role of gpg-agent.

import Foundation
import SecureMemory
import XCTest
@testable import AssuanProtocol

// MARK: - SessionTests

final class SessionTests: XCTestCase {

    // Helper: build a (session, agentIn, agentOut) triple where:
    //   * session reads from `agentOut.fileHandleForReading`,
    //   * session writes to `agentIn.fileHandleForWriting`,
    //   * the test (acting as agent) writes to `agentOut.fileHandleForWriting`,
    //   * the test reads from `agentIn.fileHandleForReading`.
    private func makeSession() -> (Session, FileHandle, FileHandle) {
        let toSession = Pipe()   // agent -> session
        let fromSession = Pipe() // session -> agent

        let session = Session(
            input: toSession.fileHandleForReading,
            output: fromSession.fileHandleForWriting
        )
        let agentWrite = toSession.fileHandleForWriting
        let agentRead = fromSession.fileHandleForReading
        return (session, agentWrite, agentRead)
    }

    // MARK: Greeting

    func testEmitGreeting() async throws {
        let (session, _, agentRead) = makeSession()
        try await session.emitGreeting()

        // Read one line back.
        let line = try readLine(agentRead)
        XCTAssertTrue(line.hasPrefix("OK Pleased to meet you, pid "),
                      "got: \(line)")
    }

    // MARK: Command transcript

    func testSimpleCommandTranscript() async throws {
        let (session, agentWrite, agentRead) = makeSession()
        defer { try? agentRead.close() }

        let transcript = "OPTION grab\nSETDESC Hello+world\nSETPROMPT Passphrase%3A\nGETPIN\nBYE\n"
        try agentWrite.write(contentsOf: Data(transcript.utf8))
        try agentWrite.close()

        let c1 = try await session.nextCommand()
        XCTAssertEqual(c1, .option(key: "grab", value: nil))

        let c2 = try await session.nextCommand()
        XCTAssertEqual(c2, .setDesc("Hello world"))

        let c3 = try await session.nextCommand()
        XCTAssertEqual(c3, .setPrompt("Passphrase:"))

        let c4 = try await session.nextCommand()
        XCTAssertEqual(c4, .getPin)

        let c5 = try await session.nextCommand()
        XCTAssertEqual(c5, .bye)

        await session.close()
    }

    // MARK: Send a D-line + OK

    func testSendDataAndOk() async throws {
        let (session, agentWrite, agentRead) = makeSession()
        defer { try? agentWrite.close() }

        // Build a SecureBytes containing "p w%d" (with space and percent).
        let pin: [UInt8] = Array("p w%d".utf8)
        let secure = SecureBytes(pin)

        try await session.send(.data(secure))
        try await session.send(.ok)

        let dLine = try readLine(agentRead)
        // Per Assuan spec: D-line payloads carry spaces verbatim (no '+'
        // substitution); only '%' / '+' / control bytes get %HH-escaped.
        // "p w%d" -> "p w%25d"
        XCTAssertEqual(dLine, "D p w%25d")

        let okLine = try readLine(agentRead)
        XCTAssertEqual(okLine, "OK")
    }

    // MARK: EOF returns .bye

    func testEOFReturnsBye() async throws {
        let (session, agentWrite, _) = makeSession()
        try agentWrite.close()
        let cmd = try await session.nextCommand()
        XCTAssertEqual(cmd, .bye)
    }

    // MARK: inquireQuality

    /// Round-trip test for `inquireQuality`. We pre-stage the agent's reply
    /// in the toSession pipe and then close the writer end so the session
    /// sees a clean EOF after consuming it — that avoids any read-side
    /// blocking on pipes whose writer is still attached.
    func testInquireQualityRoundTrip() async throws {
        let (session, agentWrite, agentRead) = makeSession()
        defer { try? agentRead.close() }

        // Pre-stage "D 42\nOK\n" (8 bytes) and close the writer. After the
        // session's readLine consumes those bytes, subsequent reads return
        // EOF — but inquireQuality won't reach that point because it returns
        // as soon as it sees the OK line.
        try agentWrite.write(contentsOf: Data("D 42\nOK\n".utf8))
        try agentWrite.close()

        let candidate = SecureBytes(Array("hunter2".utf8))
        let value = try await session.inquireQuality(candidate)
        XCTAssertEqual(value, 42)

        let line = try readLine(agentRead)
        XCTAssertTrue(line.hasPrefix("INQUIRE QUALITY "), "got: \(line)")

        await session.close()
    }

    // MARK: Session-lifetime command cap (AS-5)

    /// A peer streaming unlimited valid commands must not be able to pin the
    /// process forever: after `maxCommandsPerSession` parsed commands,
    /// `nextCommand()` throws `commandLimitExceeded`. Driven from a temp
    /// file (not a pipe) so the cap-count of small lines doesn't deadlock on
    /// the ~64 KiB pipe buffer.
    func testCommandCountCapIsEnforced() async throws {
        let cap = Session.maxCommandsPerSession

        // Build cap+1 "RESET\n" lines into a temp file.
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("assuan-cap-\(UUID().uuidString).txt")
        defer { try? FileManager.default.removeItem(at: tmp) }
        let line = Data("RESET\n".utf8)
        var blob = Data(capacity: line.count * (cap + 1))
        for _ in 0..<(cap + 1) { blob.append(line) }
        try blob.write(to: tmp)

        let input = try FileHandle(forReadingFrom: tmp)
        let output = FileHandle.nullDevice
        let session = Session(input: input, output: output)
        // XCTest awaits async teardown blocks, so close is guaranteed to
        // complete before the test case finishes (a `defer`red Task would
        // be fire-and-forget).
        addTeardownBlock { await session.close() }

        // The first `cap` calls succeed.
        for _ in 0..<cap {
            let cmd = try await session.nextCommand()
            XCTAssertEqual(cmd, .reset)
        }

        // The next call must throw the cap error, even though a valid
        // RESET line is still waiting in the buffer.
        do {
            _ = try await session.nextCommand()
            XCTFail("expected commandLimitExceeded after the cap")
        } catch SessionError.commandLimitExceeded {
            // expected
        }
    }

    // MARK: Line framing

    /// Stage `bytes` as the agent's whole output, then close the writer so the
    /// session sees EOF after consuming them.
    private func makeSession(agentSends bytes: [UInt8]) throws -> Session {
        let (session, agentWrite, _) = makeSession()
        try agentWrite.write(contentsOf: Data(bytes))
        try agentWrite.close()
        addTeardownBlock { await session.close() }
        return session
    }

    func testCRLFTerminatorsAreStripped() async throws {
        let session = try makeSession(agentSends: Array("SETDESC hi\r\nGETPIN\r\n".utf8))
        let first = try await session.nextCommand()
        XCTAssertEqual(first, .setDesc("hi"))
        let second = try await session.nextCommand()
        XCTAssertEqual(second, .getPin)
    }

    func testBlankAndCommentLinesAreSkipped() async throws {
        let session = try makeSession(agentSends: Array("\n# a comment\n\nRESET\n".utf8))
        let command = try await session.nextCommand()
        XCTAssertEqual(command, .reset)
    }

    func testFinalLineWithoutLFIsDeliveredAtEOF() async throws {
        let session = try makeSession(agentSends: Array("RESET\nGETPIN".utf8))
        let first = try await session.nextCommand()
        XCTAssertEqual(first, .reset)
        let second = try await session.nextCommand()
        XCTAssertEqual(second, .getPin)
        let third = try await session.nextCommand()
        XCTAssertEqual(third, .bye)
    }

    func testLineSplitAcrossReadsIsReassembled() async throws {
        let (session, agentWrite, _) = makeSession()
        addTeardownBlock { await session.close() }
        try agentWrite.write(contentsOf: Data("SETDESC Hel".utf8))
        let writer = Task.detached {
            try await Task.sleep(for: .milliseconds(100))
            try agentWrite.write(contentsOf: Data("lo\n".utf8))
        }
        let command = try await session.nextCommand()
        XCTAssertEqual(command, .setDesc("Hello"))
        try await writer.value
    }

    func testOverlongLineWithoutLFIsRejected() async throws {
        let session = try makeSession(agentSends: Array(repeating: 0x41, count: 5000))
        do {
            _ = try await session.nextCommand()
            XCTFail("expected malformedLine for an unterminated overlong line")
        } catch SessionError.malformedLine {
            // expected
        }
    }

    func testOverlongTerminatedLineIsRejected() async throws {
        let line = Array(repeating: UInt8(0x41), count: LineCodec.maxLineLength + 1) + [0x0A]
        let session = try makeSession(agentSends: line)
        do {
            _ = try await session.nextCommand()
            XCTFail("expected malformedLine for a 1001-byte line")
        } catch SessionError.malformedLine {
            // expected
        }
    }

    func testMaxLengthLineIsAccepted() async throws {
        let argument = String(repeating: "a", count: LineCodec.maxLineLength - 8)
        let session = try makeSession(agentSends: Array("SETDESC \(argument)\n".utf8))
        let command = try await session.nextCommand()
        XCTAssertEqual(command, .setDesc(argument))
    }

    func testInvalidUTF8LineIsRejected() async throws {
        let session = try makeSession(agentSends: [0x52, 0xFF, 0xFE, 0x0A])
        do {
            _ = try await session.nextCommand()
            XCTFail("expected malformedLine for invalid UTF-8")
        } catch SessionError.malformedLine {
            // expected
        }
    }

    func testSessionRecoversAfterInvalidUTF8Line() async throws {
        let session = try makeSession(agentSends: [0x52, 0xFF, 0x0A] + Array("RESET\n".utf8))
        await assertMalformed(session)
        let next = try await session.nextCommand()
        XCTAssertEqual(next, .reset)
    }

    func testSessionRecoversAfterOverlongLine() async throws {
        let overlong = String(repeating: "A", count: LineCodec.maxLineLength + 500)
        let session = try makeSession(agentSends: Array("\(overlong)\nRESET\n".utf8))
        await assertMalformed(session)
        let next = try await session.nextCommand()
        XCTAssertEqual(next, .reset)
    }

    func testSessionSkipsRestOfOverlongLineWhoseTerminatorArrivesLater() async throws {
        let (session, agentWrite, _) = makeSession()
        addTeardownBlock { await session.close() }
        try agentWrite.write(contentsOf: Data(repeating: 0x41, count: 3000))
        await assertMalformed(session)

        try agentWrite.write(contentsOf: Data("AAAA\nRESET\n".utf8))
        try agentWrite.close()
        let next = try await session.nextCommand()
        XCTAssertEqual(next, .reset, "the tail of the overlong line must not parse as a command")
    }

    func testSessionRecoversAfterInvalidTrailingLineAtEOF() async throws {
        let session = try makeSession(agentSends: [0xFF])
        await assertMalformed(session)
        let next = try await session.nextCommand()
        XCTAssertEqual(next, .bye)
    }

    private func assertMalformed(
        _ session: Session, file: StaticString = #filePath, line: UInt = #line
    ) async {
        do {
            _ = try await session.nextCommand()
            XCTFail("expected malformedLine", file: file, line: line)
        } catch SessionError.malformedLine {
            // expected
        } catch {
            XCTFail("unexpected error \(error)", file: file, line: line)
        }
    }

    // MARK: Secret D-line chunking

    func testLongSecretIsSplitIntoBoundedDataLines() async throws {
        let (session, _, agentRead) = makeSession()
        // Every byte escapes to %HH, the worst case for line length.
        let secret = SecureBytes(Array(repeating: UInt8(0x2B), count: 700))
        try await session.send(.data(secret))
        try await session.send(.ok)

        var recovered: [UInt8] = []
        var lines = 0
        while true {
            let line = try readLine(agentRead)
            if line == "OK" { break }
            XCTAssertTrue(line.hasPrefix("D "), "got: \(line)")
            XCTAssertLessThanOrEqual(line.utf8.count, LineCodec.maxLineLength)
            recovered += try LineCodec.unescapeFromDataLine(String(line.dropFirst(2)))
            lines += 1
        }
        XCTAssertEqual(lines, 3, "700 source bytes at 332 per line is three lines")
        XCTAssertEqual(recovered, Array(repeating: 0x2B, count: 700))
    }

    func testEmptySecretSendsEmptyDataLine() async throws {
        let (session, _, agentRead) = makeSession()
        try await session.send(.data(SecureBytes(capacity: 8)))
        let line = try readLine(agentRead)
        XCTAssertEqual(line, "D ")
    }

    // MARK: inquireQuality wire format

    func testInquireQualityEscapesCandidate() async throws {
        let (session, agentWrite, agentRead) = makeSession()
        defer { try? agentRead.close() }
        try agentWrite.write(contentsOf: Data("D -7\nOK\n".utf8))
        try agentWrite.close()

        let value = try await session.inquireQuality(SecureBytes(Array("a b+%\u{7F}".utf8)))
        XCTAssertEqual(value, -7)
        let line = try readLine(agentRead)
        XCTAssertEqual(line, "INQUIRE QUALITY a b%2B%25%7F")
        await session.close()
    }

    func testInquireQualityClampsToRange() async throws {
        let (session, agentWrite, agentRead) = makeSession()
        defer { try? agentRead.close() }
        try agentWrite.write(contentsOf: Data("D 9999\nOK\n".utf8))
        try agentWrite.close()
        let value = try await session.inquireQuality(SecureBytes(Array("x".utf8)))
        XCTAssertEqual(value, 100)
    }

    func testInquireQualityOverlongCandidateReturnsZeroWithoutWriting() async throws {
        let (session, agentWrite, agentRead) = makeSession()
        try agentWrite.close()
        let candidate = SecureBytes(Array(repeating: UInt8(0x61), count: 329))
        let value = try await session.inquireQuality(candidate)
        XCTAssertEqual(value, 0)
        await session.close()
        // Session closed its output end, so a read sees EOF with nothing sent.
        XCTAssertEqual(try agentRead.readToEnd() ?? Data(), Data())
    }

    // MARK: ERR encoding

    func testSendErr() async throws {
        let (session, _, agentRead) = makeSession()
        try await session.send(.err(code: AssuanError.canceled, message: "Operation cancelled"))
        let line = try readLine(agentRead)
        XCTAssertEqual(line, "ERR 83886090 Operation cancelled")
    }

    // MARK: Status line

    func testSendStatus() async throws {
        let (session, _, agentRead) = makeSession()
        try await session.send(.status(keyword: "PASSWORD_FROM_CACHE", parameters: ""))
        let line = try readLine(agentRead)
        XCTAssertEqual(line, "S PASSWORD_FROM_CACHE")
    }

    // MARK: - Test helpers

    /// Read up to and including the next LF from `fh`, returning the line
    /// without the trailing LF. Synchronous; used after we know the writer
    /// has already produced output.
    private func readLine(_ fh: FileHandle) throws -> String {
        var buffer = Data()
        while true {
            let chunk = try fh.read(upToCount: 1) ?? Data()
            if chunk.isEmpty {
                // EOF
                guard let s = String(data: buffer, encoding: .utf8) else {
                    throw NSError(domain: "test", code: 1)
                }
                return s
            }
            if chunk[0] == 0x0A {
                guard let s = String(data: buffer, encoding: .utf8) else {
                    throw NSError(domain: "test", code: 2)
                }
                return s
            }
            buffer.append(chunk)
        }
    }
}

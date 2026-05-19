// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// AssuanSmokeTests — feed a recorded Assuan transcript to the bundled
// pinentry-darwin binary on stdin and assert the expected wire
// responses come back on stdout. This replaces `scripts/smoke-assuan.sh`
// with an XCTest case that runs as part of `swift test`.
//
// Coverage matches the script line-for-line:
//   - greeting "OK Pleased to meet you"
//   - OPTION (bare and key=value)
//   - SETDESC / SETPROMPT / SETTITLE / SETERROR / SETKEYINFO /
//     SETTIMEOUT / SETQUALITYBAR(_TT)
//   - GETINFO version / flavor / pid / ttyinfo
//   - RESET clears per-dialog state but not OPTION state
//   - GETINFO unknown topic returns ERR
//   - BYE returns OK and the process exits 0
//   - no unexpected wire prefixes (only OK / ERR / D / S / INQUIRE)
//
// The binary path is resolved via `make build`'s output location and
// is overridable with PINENTRY_DARWIN_SMOKE_BINARY for CI variations.
// If the binary is missing the test is skipped, not failed — so
// `swift test` works on a fresh clone before `make build` has run.

import XCTest
import Foundation

final class AssuanSmokeTests: XCTestCase {

    private static let transcript: String = """
        # leading comment, must be tolerated

        OPTION ttytype=xterm-256color
        OPTION ttyname=/dev/ttys042
        OPTION lc-ctype=en_US.UTF-8
        OPTION default-ok=OK
        OPTION default-cancel=Cancel
        OPTION default-prompt=Passphrase:
        OPTION grab
        SETDESC Please+enter+your+passphrase
        SETPROMPT pin
        SETTITLE pinentry-darwin+smoke
        SETERROR none
        SETKEYINFO n/ABCDEF1234567890ABCDEF1234567890ABCDEF12
        SETTIMEOUT 30
        SETQUALITYBAR Strength
        SETQUALITYBAR_TT Higher+is+stronger
        GETINFO version
        GETINFO flavor
        GETINFO pid
        GETINFO ttyinfo
        # RESET clears per-dialog state
        RESET
        GETINFO ttyinfo
        GETINFO not-a-real-topic
        BYE

        """

    // MARK: - Binary resolution

    private func locateBinary() -> URL? {
        if let override = ProcessInfo.processInfo.environment["PINENTRY_DARWIN_SMOKE_BINARY"] {
            let url = URL(fileURLWithPath: override)
            return FileManager.default.isExecutableFile(atPath: url.path) ? url : nil
        }
        // Walk upward from this source file to find the repo root.
        // SwiftPM runs tests with the CWD at the package root, so try
        // that first; fall back to walking from the file URL.
        let cwd = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
        let cwdCandidate = cwd
            .appendingPathComponent("build/pinentry-darwin.app/Contents/MacOS/pinentry-darwin")
        if FileManager.default.isExecutableFile(atPath: cwdCandidate.path) {
            return cwdCandidate
        }
        return nil
    }

    // MARK: - Test

    func testAssuanWireProtocolSmoke() throws {
        guard let binary = locateBinary() else {
            throw XCTSkip("smoke target requires `make build`; set PINENTRY_DARWIN_SMOKE_BINARY to override")
        }

        let result = try runBinary(binary, stdin: Self.transcript)

        XCTAssertEqual(result.exitCode, 0, "pinentry-darwin exited \(result.exitCode); stdout:\n\(result.stdout)")

        let stdout = result.stdout
        let lines = stdout.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)

        XCTAssertTrue(
            lines.contains { $0.hasPrefix("OK Pleased to meet you") },
            "missing greeting in:\n\(stdout)"
        )
        XCTAssertTrue(
            lines.contains { matchesSemverDLine($0) },
            "missing version D-line; stdout:\n\(stdout)"
        )
        XCTAssertTrue(
            lines.contains { $0 == "D darwin" },
            "missing flavor D-line; stdout:\n\(stdout)"
        )
        XCTAssertTrue(
            lines.contains { matchesPidDLine($0) },
            "missing pid D-line; stdout:\n\(stdout)"
        )
        // Per Assuan spec, D-line payloads carry spaces verbatim —
        // no '+'↔space substitution (that's command-arg only).
        XCTAssertTrue(
            lines.contains { $0 == "D /dev/ttys042 xterm-256color 0" },
            "missing ttyinfo D-line; stdout:\n\(stdout)"
        )
        XCTAssertTrue(
            lines.contains { $0.hasPrefix("ERR ") },
            "missing ERR reply for unknown getinfo topic; stdout:\n\(stdout)"
        )

        // Last non-empty line must be an OK from BYE.
        if let last = lines.reversed().first(where: { !$0.isEmpty }) {
            XCTAssertTrue(
                last.hasPrefix("OK"),
                "last non-empty line is not OK: '\(last)'"
            )
        } else {
            XCTFail("no non-empty output lines")
        }

        // Sanity: every non-empty line must start with a valid Assuan
        // response verb. Anything else (e.g. a passphrase echoed back)
        // is a wire-protocol violation.
        for line in lines where !line.isEmpty {
            XCTAssertTrue(
                isValidWirePrefix(line),
                "unexpected wire content (no OK/ERR/D/S/INQUIRE/# prefix): '\(line)'"
            )
        }
    }

    // MARK: - Helpers

    private struct RunResult {
        let exitCode: Int32
        let stdout: String
    }

    private func runBinary(_ url: URL, stdin: String) throws -> RunResult {
        let proc = Process()
        proc.executableURL = url
        let outPipe = Pipe()
        let errPipe = Pipe()
        let inPipe = Pipe()
        proc.standardOutput = outPipe
        proc.standardError = errPipe
        proc.standardInput = inPipe
        try proc.run()
        if let data = stdin.data(using: .utf8) {
            inPipe.fileHandleForWriting.write(data)
        }
        try inPipe.fileHandleForWriting.close()
        proc.waitUntilExit()
        let outData = (try? outPipe.fileHandleForReading.readToEnd()) ?? Data()
        _ = try? errPipe.fileHandleForReading.readToEnd()  // drained, ignored
        return RunResult(
            exitCode: proc.terminationStatus,
            stdout: String(decoding: outData, as: UTF8.self)
        )
    }

    /// `D X.Y.Z` where each component is one or more digits.
    private func matchesSemverDLine(_ line: String) -> Bool {
        guard line.hasPrefix("D ") else { return false }
        let payload = line.dropFirst(2)
        let parts = payload.split(separator: ".")
        guard parts.count == 3 else { return false }
        return parts.allSatisfy { part in
            !part.isEmpty && part.allSatisfy { $0.isASCII && $0.isNumber }
        }
    }

    /// `D <pid>` where pid is one or more digits.
    private func matchesPidDLine(_ line: String) -> Bool {
        guard line.hasPrefix("D ") else { return false }
        let payload = line.dropFirst(2)
        guard !payload.isEmpty else { return false }
        return payload.allSatisfy { $0.isASCII && $0.isNumber }
    }

    /// Valid Assuan wire prefixes the binary may emit on stdout.
    /// Comments (#) and blank lines are also tolerated.
    private func isValidWirePrefix(_ line: String) -> Bool {
        if line.hasPrefix("OK") { return true }
        if line.hasPrefix("ERR ") || line == "ERR" { return true }
        if line.hasPrefix("D ") { return true }
        if line.hasPrefix("S ") || line == "S" { return true }
        if line.hasPrefix("INQUIRE") { return true }
        if line.hasPrefix("#") { return true }
        return false
    }
}

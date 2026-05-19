// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// RealProcessRunnerTests — pin the pipe-drain contract.
//
// macOS pipe buffers cap around 64 KiB. Without an active reader, a
// child that writes more than that blocks on write(2), which prevents
// Process.terminationHandler from firing. RealProcessRunner must drain
// stdout / stderr concurrently with the child via readabilityHandler so
// payloads larger than the pipe buffer complete cleanly.

import XCTest
@testable import SSHIdentity

final class RealProcessRunnerTests: XCTestCase {

    // Pipe more than the kernel pipe buffer through dd. Pre-fix this
    // hangs forever waiting for terminationHandler-driven readToEnd().
    // 4096 * 64 = 262144 bytes — well above the 64 KiB ceiling.
    func testLargeStdoutDoesNotDeadlock() async throws {
        let runner = RealProcessRunner()
        let result = try await runner.run(
            executable: "/bin/dd",
            arguments: ["if=/dev/zero", "bs=4096", "count=64", "status=none"],
            stdin: nil
        )
        XCTAssertEqual(result.exitCode, 0)
        XCTAssertGreaterThanOrEqual(result.stdout.utf8.count, 4096 * 64)
    }

    // Symmetric stderr drain. /bin/dd without status=none writes its
    // "N+0 records in / out" summary to stderr; the child cannot exit
    // until that write completes, so a missing stderr drain also hangs.
    func testStderrDrainsConcurrently() async throws {
        let runner = RealProcessRunner()
        let result = try await runner.run(
            executable: "/bin/dd",
            arguments: ["if=/dev/zero", "bs=4096", "count=64"],
            stdin: nil
        )
        XCTAssertEqual(result.exitCode, 0)
        XCTAssertGreaterThanOrEqual(result.stdout.utf8.count, 4096 * 64)
        XCTAssertFalse(result.stderr.isEmpty)
    }

    // Small-output regression check — make sure the new drain shape
    // didn't introduce a startup race that drops short stdout.
    func testSmallStdoutCompletes() async throws {
        let runner = RealProcessRunner()
        let result = try await runner.run(
            executable: "/bin/echo",
            arguments: ["hello", "world"],
            stdin: nil
        )
        XCTAssertEqual(result.exitCode, 0)
        XCTAssertEqual(result.stdout, "hello world\n")
        XCTAssertTrue(result.stderr.isEmpty)
    }
}

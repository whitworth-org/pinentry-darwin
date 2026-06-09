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
            stdin: nil,
            timeout: .seconds(30)
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
            stdin: nil,
            timeout: .seconds(30)
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
            stdin: nil,
            timeout: .seconds(30)
        )
        XCTAssertEqual(result.exitCode, 0)
        XCTAssertEqual(result.stdout, "hello world\n")
        XCTAssertTrue(result.stderr.isEmpty)
    }

    // L-6 / L-12: a hung child must time out (not block forever) and the
    // continuation must be resumed exactly once. `/bin/sleep 30` with a
    // sub-second timeout exercises the timeout path; the guard prevents a
    // second resume when terminationHandler fires after SIGTERM.
    func testHungChildTimesOut() async throws {
        let runner = RealProcessRunner()
        let start = ContinuousClock.now
        do {
            _ = try await runner.run(
                executable: "/bin/sleep",
                arguments: ["30"],
                stdin: nil,
                timeout: .milliseconds(300)
            )
            XCTFail("expected timedOut")
        } catch let ProcessRunnerError.timedOut(executable, _) {
            XCTAssertEqual(executable, "/bin/sleep")
        } catch {
            XCTFail("unexpected: \(error)")
        }
        // Returned well before the child's own 30s runtime.
        let elapsed = ContinuousClock.now - start
        XCTAssertLessThan(elapsed, .seconds(10))
    }

    // Resume-exactly-once on the success path: the child exits cleanly
    // (terminationHandler resumes) well before a short-but-not-tiny
    // timeout. The timeout task still fires afterwards and tries to
    // resume again; without the single-shot guard that second resume
    // would trap the whole test process. The deferred sleep gives the
    // timeout task time to fire so a broken guard would crash here.
    func testTimeoutAfterCleanExitIsNoOp() async throws {
        let runner = RealProcessRunner()
        let result = try await runner.run(
            executable: "/bin/echo",
            arguments: ["ok"],
            stdin: nil,
            timeout: .milliseconds(200)
        )
        XCTAssertEqual(result.exitCode, 0)
        XCTAssertEqual(result.stdout, "ok\n")
        // Outlive the timeout window: the timeout task's late resume must
        // be swallowed by the guard rather than crash the process.
        try await Task.sleep(for: .milliseconds(400))
    }
}

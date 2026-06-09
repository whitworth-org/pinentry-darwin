// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// ProcessRunner.swift — minimal `Foundation.Process` wrapper used by
// `SCAuthClient` and `SSHAddClient`. Both clients invoke Apple CLI
// binaries with pinned absolute paths and explicit argv arrays — no
// shell, no string interpolation — so the only thing this helper has
// to provide is launch + capture + exit-code, with a typed result.

import Foundation
import os

private let log = Logger(
    subsystem: "org.whitworth.pinentry-darwin",
    category: "ssh.process"
)

// MARK: - Result type

public struct ProcessResult: Sendable, Equatable {
    public let exitCode: Int32
    public let stdout: String
    public let stderr: String

    public init(exitCode: Int32, stdout: String, stderr: String) {
        self.exitCode = exitCode
        self.stdout = stdout
        self.stderr = stderr
    }

    public var didSucceed: Bool { exitCode == 0 }
}

// MARK: - Errors

public enum ProcessRunnerError: Error, Equatable, Sendable {
    /// The child did not exit within the per-operation `timeout`. The
    /// child was sent `SIGTERM` before this error was thrown.
    case timedOut(executable: String, seconds: Double)
}

// MARK: - Runner protocol

/// Protocol so tests can inject a fake runner without spawning real
/// subprocesses. The default implementation lives in
/// `RealProcessRunner` below.
public protocol ProcessRunner: Sendable {
    /// Launch `executable` with `arguments`, optionally writing `stdin`,
    /// and capture stdout/stderr + exit code. `timeout` bounds the wall
    /// time: a child that has not exited by then is sent `SIGTERM` and
    /// the call throws `ProcessRunnerError.timedOut`. Callers pick the
    /// ceiling per operation — long for Touch-ID-gated work, short for
    /// agent queries.
    func run(
        executable: String,
        arguments: [String],
        stdin: Data?,
        timeout: Duration
    ) async throws -> ProcessResult
}

// MARK: - Real runner

public struct RealProcessRunner: ProcessRunner {
    public init() {}

    /// Single-shot resume guard. `terminationHandler`, the timeout task,
    /// and the launch-failure `catch` may all try to resolve the same
    /// `CheckedContinuation`; a double-resume traps. The first caller to
    /// flip the flag under the lock wins and resumes — the rest are
    /// no-ops. The continuation is wrapped in a `final class` box so the
    /// (non-`Sendable`) continuation can be captured by the `Sendable`
    /// timeout closure exactly once and then dropped.
    private final class ResumeGuard: @unchecked Sendable {
        private let didResume = OSAllocatedUnfairLock<Bool>(initialState: false)
        private var cont: CheckedContinuation<ProcessResult, Error>?

        init(_ cont: CheckedContinuation<ProcessResult, Error>) {
            self.cont = cont
        }

        /// Returns true exactly once — for the first caller to claim the
        /// resume. Subsequent callers get false and must not touch the
        /// continuation.
        private func claim() -> Bool {
            didResume.withLock { resumed in
                if resumed { return false }
                resumed = true
                return true
            }
        }

        func resume(returning value: ProcessResult) {
            guard claim() else { return }
            let c = cont
            cont = nil
            c?.resume(returning: value)
        }

        func resume(throwing error: Error) {
            guard claim() else { return }
            let c = cont
            cont = nil
            c?.resume(throwing: error)
        }
    }

    /// Sendable handle to the live `Process` so the cancellation handler
    /// can `terminate()` a child it does not otherwise own. Holds the
    /// process behind the same kind of unfair-lock used elsewhere here.
    private final class ProcessBox: @unchecked Sendable {
        private let state = OSAllocatedUnfairLock<Process?>(initialState: nil)
        func set(_ proc: Process) { state.withLock { $0 = proc } }
        func terminateIfRunning() {
            state.withLock { proc in
                if let proc, proc.isRunning { proc.terminate() }
            }
        }
    }

    public func run(
        executable: String,
        arguments: [String],
        stdin: Data?,
        timeout: Duration
    ) async throws -> ProcessResult {
        let procBox = ProcessBox()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { cont in
                let guarded = ResumeGuard(cont)
                let proc = Process()
                proc.executableURL = URL(fileURLWithPath: executable)
                proc.arguments = arguments
                procBox.set(proc)

                let outPipe = Pipe()
                let errPipe = Pipe()
                let inPipe = Pipe()
                proc.standardOutput = outPipe
                proc.standardError = errPipe
                proc.standardInput = inPipe

                // Drain stdout/stderr concurrently with the child. macOS
                // pipe buffers cap around 64 KiB — without an active
                // reader, a child that writes more than that blocks on
                // `write(2)`, which prevents `terminationHandler` from
                // firing and deadlocks the call. `readabilityHandler`
                // runs on Foundation's internal queue, so accumulators
                // are protected by an unfair-lock (the simplest correct
                // primitive for exclusive append from arbitrary queues).
                let outBuf = OSAllocatedUnfairLock<Data>(initialState: Data())
                let errBuf = OSAllocatedUnfairLock<Data>(initialState: Data())

                outPipe.fileHandleForReading.readabilityHandler = { handle in
                    let chunk = handle.availableData
                    if chunk.isEmpty {
                        // EOF: detach to break the retain cycle the
                        // handler closure forms with the FileHandle.
                        handle.readabilityHandler = nil
                    } else {
                        outBuf.withLock { $0.append(chunk) }
                    }
                }
                errPipe.fileHandleForReading.readabilityHandler = { handle in
                    let chunk = handle.availableData
                    if chunk.isEmpty {
                        handle.readabilityHandler = nil
                    } else {
                        errBuf.withLock { $0.append(chunk) }
                    }
                }

                proc.terminationHandler = { p in
                    // Detach handlers so they cannot fire concurrently
                    // with the trailing readToEnd below.
                    outPipe.fileHandleForReading.readabilityHandler = nil
                    errPipe.fileHandleForReading.readabilityHandler = nil
                    // Final drain: anything Foundation buffered after the
                    // last readabilityHandler tick lands here.
                    let trailingOut = (try? outPipe.fileHandleForReading.readToEnd()) ?? Data()
                    let trailingErr = (try? errPipe.fileHandleForReading.readToEnd()) ?? Data()
                    let outData = outBuf.withLock { $0 + trailingOut }
                    let errData = errBuf.withLock { $0 + trailingErr }
                    let result = ProcessResult(
                        exitCode: p.terminationStatus,
                        stdout: String(decoding: outData, as: UTF8.self),
                        stderr: String(decoding: errData, as: UTF8.self)
                    )
                    // Resume through the guard: if the timeout already
                    // fired and terminated the child, this is a no-op.
                    guarded.resume(returning: result)
                }

                do {
                    try proc.run()
                    if let stdin {
                        inPipe.fileHandleForWriting.write(stdin)
                    }
                    try? inPipe.fileHandleForWriting.close()
                } catch {
                    log.error("process run failed: \(String(describing: error), privacy: .private)")
                    // proc.run() threw before launch, so
                    // terminationHandler will not fire. Detach the
                    // readability handlers we installed above to break
                    // their retain cycles before resuming on the error
                    // path.
                    outPipe.fileHandleForReading.readabilityHandler = nil
                    errPipe.fileHandleForReading.readabilityHandler = nil
                    guarded.resume(throwing: error)
                    return
                }

                // Per-operation timeout. A hung child (Touch ID never
                // answered, dead SSH_AUTH_SOCK) would otherwise wedge the
                // caller forever. SIGTERM the child and resolve with a
                // timeout error; the guard makes whichever of {this,
                // terminationHandler, the cancel-driven terminate} fires
                // first the sole resumer.
                Task {
                    try? await Task.sleep(for: timeout)
                    procBox.terminateIfRunning()
                    guarded.resume(throwing: ProcessRunnerError.timedOut(
                        executable: executable,
                        seconds: Double(timeout.components.seconds)
                    ))
                }
            }
        } onCancel: {
            // Cooperative cancellation: SIGTERM the child so the await
            // returns promptly instead of hanging. terminationHandler
            // then resolves the continuation with the terminated-child
            // result; the single-shot guard keeps that the only resume.
            procBox.terminateIfRunning()
        }
    }
}

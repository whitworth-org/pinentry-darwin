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

// MARK: - Runner protocol

/// Protocol so tests can inject a fake runner without spawning real
/// subprocesses. The default implementation lives in
/// `RealProcessRunner` below.
public protocol ProcessRunner: Sendable {
    func run(
        executable: String,
        arguments: [String],
        stdin: Data?
    ) async throws -> ProcessResult
}

// MARK: - Real runner

public struct RealProcessRunner: ProcessRunner {
    public init() {}

    public func run(
        executable: String,
        arguments: [String],
        stdin: Data?
    ) async throws -> ProcessResult {
        try await withCheckedThrowingContinuation { cont in
            let proc = Process()
            proc.executableURL = URL(fileURLWithPath: executable)
            proc.arguments = arguments

            let outPipe = Pipe()
            let errPipe = Pipe()
            let inPipe = Pipe()
            proc.standardOutput = outPipe
            proc.standardError = errPipe
            proc.standardInput = inPipe

            // Drain stdout/stderr concurrently with the child. macOS pipe
            // buffers cap around 64 KiB — without an active reader, a
            // child that writes more than that blocks on `write(2)`,
            // which prevents `terminationHandler` from firing and
            // deadlocks the call. `readabilityHandler` runs on
            // Foundation's internal queue, so accumulators are protected
            // by an unfair-lock (the simplest correct primitive for
            // exclusive append from arbitrary queues).
            let outBuf = OSAllocatedUnfairLock<Data>(initialState: Data())
            let errBuf = OSAllocatedUnfairLock<Data>(initialState: Data())

            outPipe.fileHandleForReading.readabilityHandler = { handle in
                let chunk = handle.availableData
                if chunk.isEmpty {
                    // EOF: detach to break the retain cycle the handler
                    // closure forms with the FileHandle.
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
                // Detach handlers so they cannot fire concurrently with
                // the trailing readToEnd below.
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
                cont.resume(returning: result)
            }

            do {
                try proc.run()
                if let stdin {
                    inPipe.fileHandleForWriting.write(stdin)
                }
                try? inPipe.fileHandleForWriting.close()
            } catch {
                log.error("process run failed: \(String(describing: error), privacy: .public)")
                // proc.run() threw before launch, so terminationHandler
                // will not fire. Detach the readability handlers we
                // installed above to break their retain cycles before
                // resuming on the error path.
                outPipe.fileHandleForReading.readabilityHandler = nil
                errPipe.fileHandleForReading.readabilityHandler = nil
                cont.resume(throwing: error)
            }
        }
    }
}

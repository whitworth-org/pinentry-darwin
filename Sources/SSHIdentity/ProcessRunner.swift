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

            proc.terminationHandler = { p in
                let outData = (try? outPipe.fileHandleForReading.readToEnd()) ?? Data()
                let errData = (try? errPipe.fileHandleForReading.readToEnd()) ?? Data()
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
                cont.resume(throwing: error)
            }
        }
    }
}

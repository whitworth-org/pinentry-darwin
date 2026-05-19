// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// ProcessRunner.swift — synchronous Foundation.Process wrapper used by
// the audit checks to invoke /usr/bin/lipo, /usr/bin/otool,
// /usr/bin/codesign, /usr/bin/xcrun, /usr/bin/plutil etc.
//
// All callers pass explicit argv arrays with pinned absolute binary
// paths so there is no shell expansion of user-controlled values.

import Foundation

public struct ProcRunResult {
    public let exitCode: Int32
    public let stdout: String
    public let stderr: String

    public var didSucceed: Bool { exitCode == 0 }
}

/// Run a binary synchronously and capture stdout/stderr. Throws if
/// `Process.run()` itself fails (binary missing, EPERM, etc.).
public func runProcess(
    _ executable: String,
    _ arguments: [String]
) throws -> ProcRunResult {
    let proc = Process()
    proc.executableURL = URL(fileURLWithPath: executable)
    proc.arguments = arguments
    let outPipe = Pipe()
    let errPipe = Pipe()
    proc.standardOutput = outPipe
    proc.standardError = errPipe
    try proc.run()
    proc.waitUntilExit()
    let outData = (try? outPipe.fileHandleForReading.readToEnd()) ?? Data()
    let errData = (try? errPipe.fileHandleForReading.readToEnd()) ?? Data()
    return ProcRunResult(
        exitCode: proc.terminationStatus,
        stdout: String(decoding: outData, as: UTF8.self),
        stderr: String(decoding: errData, as: UTF8.self)
    )
}

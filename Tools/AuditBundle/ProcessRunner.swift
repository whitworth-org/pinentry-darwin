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

/// Reads a pipe to EOF on a background queue so the child never blocks on a
/// full pipe buffer (about 64 KiB) while the caller waits for it to exit.
private final class PipeDrain: @unchecked Sendable {
    // Written once on the drain queue and read only after `group.wait()`, which orders
    // the two accesses.
    private(set) var data = Data()

    init(_ pipe: Pipe, group: DispatchGroup) {
        group.enter()
        DispatchQueue.global().async {
            self.data = (try? pipe.fileHandleForReading.readToEnd()) ?? Data()
            group.leave()
        }
    }
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
    let group = DispatchGroup()
    let out = PipeDrain(outPipe, group: group)
    let err = PipeDrain(errPipe, group: group)
    proc.waitUntilExit()
    group.wait()
    return ProcRunResult(
        exitCode: proc.terminationStatus,
        stdout: String(decoding: out.data, as: UTF8.self),
        stderr: String(decoding: err.data, as: UTF8.self)
    )
}

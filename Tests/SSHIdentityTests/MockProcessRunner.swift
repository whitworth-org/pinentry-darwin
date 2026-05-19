// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// MockProcessRunner — a test-only `ProcessRunner` that records calls
// and replays scripted `ProcessResult` values. Used by SCAuthClient
// and SSHIdentityManager tests so we never spawn a real subprocess in
// the hermetic suite.

import Foundation
@testable import SSHIdentity

/// Records one invocation passed to `ProcessRunner.run`.
struct RecordedInvocation: Sendable, Equatable {
    let executable: String
    let arguments: [String]
}

/// Test runner that answers a sequence of canned responses keyed by
/// argv prefix. `responses` is consumed FIFO when no key matches.
actor MockProcessRunner: ProcessRunner {
    private var byArgs: [[String]: ProcessResult]
    private var fallback: [ProcessResult]
    private(set) var calls: [RecordedInvocation] = []

    init(
        byArgs: [[String]: ProcessResult] = [:],
        fallback: [ProcessResult] = []
    ) {
        self.byArgs = byArgs
        self.fallback = fallback
    }

    func run(
        executable: String,
        arguments: [String],
        stdin: Data?
    ) async throws -> ProcessResult {
        calls.append(RecordedInvocation(executable: executable, arguments: arguments))
        if let canned = byArgs[arguments] {
            return canned
        }
        if !fallback.isEmpty {
            return fallback.removeFirst()
        }
        return ProcessResult(exitCode: 0, stdout: "", stderr: "")
    }
}

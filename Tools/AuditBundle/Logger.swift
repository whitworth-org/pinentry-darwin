// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// Logger.swift — minimal stdout/stderr findings emitter used by the
// audit-bundle executable. We deliberately do NOT use os.Logger here:
// the audit binary is a CI / shell tool, not a long-running process,
// and its consumers grep its output to detect regressions. Stable,
// parseable text on stdout/stderr is the contract.
//
// Output contract (matches the legacy `scripts/audit-bundle.sh`):
//   - `audit: FAIL — <reason>` per failed assertion, on stderr
//   - `audit: PASS (<bundle>)` on success, on stdout
//   - `audit: FAIL — <n> issue(s) found in <bundle>` summary, on stderr
//   - exit code 0 (pass) / 1 (any fail) / 2 (missing bundle)

import Foundation

public struct Findings {
    public private(set) var count: Int = 0
    private let stderr = FileHandle.standardError

    public init() {}

    public mutating func fail(_ reason: String) {
        let line = "audit: FAIL — \(reason)\n"
        if let data = line.data(using: .utf8) {
            stderr.write(data)
        }
        count += 1
    }
}

public func emitPass(_ bundle: String) {
    print("audit: PASS (\(bundle))")
}

public func emitSummary(_ bundle: String, fails: Int) {
    let line = "audit: FAIL — \(fails) issue(s) found in \(bundle)\n"
    if let data = line.data(using: .utf8) {
        FileHandle.standardError.write(data)
    }
}

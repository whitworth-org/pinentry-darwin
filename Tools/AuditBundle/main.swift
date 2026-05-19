// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// main.swift — entry point for the `audit-bundle` SwiftPM executable
// target. Drop-in replacement for `scripts/audit-bundle.sh`.
//
// Usage (mirrors the legacy script):
//   swift run audit-bundle                        # default bundle path
//   swift run audit-bundle path/to/app            # explicit path
//   swift run audit-bundle --release              # require Developer ID
//                                                   + stapled notarization
//   swift run audit-bundle --release path/to/app
//
// Exit codes:
//   0 — all checks pass
//   1 — at least one check failed
//   2 — bundle path missing
//
// Override the expected team identifier with PINENTRY_DARWIN_TEAM_ID
// (default KHJA84J3YW). Useful for CI building under a different
// developer identity.

import Foundation

let argv = CommandLine.arguments
var releaseMode = false
var bundlePath = "build/pinentry-darwin.app"

var i = 1
while i < argv.count {
    let arg = argv[i]
    if arg == "--release" {
        releaseMode = true
    } else if arg == "--help" || arg == "-h" {
        print("""
            Usage: audit-bundle [--release] [path/to/app]
              --release   require Developer ID + stapled notarization
              path        defaults to build/pinentry-darwin.app
            """)
        exit(0)
    } else {
        bundlePath = arg
    }
    i += 1
}

var isDirectory: ObjCBool = false
if !FileManager.default.fileExists(atPath: bundlePath, isDirectory: &isDirectory)
    || !isDirectory.boolValue {
    let line = "audit: bundle not found at \(bundlePath)\n"
    if let data = line.data(using: .utf8) {
        FileHandle.standardError.write(data)
    }
    exit(2)
}

// Repo root is the current working directory by convention. `make`
// and CI invoke the audit from the repo root; for `swift run` from a
// non-root directory, set `--repo-root <path>` explicitly. This
// matches the legacy `scripts/audit-bundle.sh` which computed its
// REPO_ROOT relative to `$0` and then used it only to find the
// fallback entitlements file at `<root>/App/pinentry-darwin.entitlements`.
let repoRoot = FileManager.default.currentDirectoryPath

let paths = BundlePaths(bundle: bundlePath, repoRoot: repoRoot)
var findings = Findings()

checkBundleStructure(paths, &findings)
checkMachOShape(paths, &findings)
checkInfoPlist(paths, &findings)
checkEntitlements(paths, releaseMode: releaseMode, &findings)
let expectedTeam = ProcessInfo.processInfo.environment["PINENTRY_DARWIN_TEAM_ID"] ?? "KHJA84J3YW"
checkCodesign(paths, releaseMode: releaseMode, expectedTeamId: expectedTeam, &findings)

if findings.count == 0 {
    emitPass(bundlePath)
    exit(0)
}
emitSummary(bundlePath, fails: findings.count)
exit(1)

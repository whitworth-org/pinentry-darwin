// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// main.swift — entry point for the `audit-bundle` SwiftPM executable
// target. The bundle-audit enforcement lives in the check predicates in
// Tools/AuditBundle/Checks.swift (the former scripts/audit-bundle.sh was
// retired in favour of this tool).
//
// Usage:
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
// Override the expected team identifier with PINENTRY_DARWIN_TEAM_ID.
// If unset, audit-bundle falls back to `defaultTeamIdentifier` below.
// Useful for CI building under a different developer identity.

import Foundation

let defaultTeamIdentifier = "KHJA84J3YW"

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
// and CI invoke the audit from the repo root. It is used only by
// loadEntitlements() in Tools/AuditBundle/Checks.swift to find the
// fallback entitlements source at
// `<root>/App/pinentry-darwin.entitlements` when the bundle is unsigned.
let repoRoot = FileManager.default.currentDirectoryPath

let paths = BundlePaths(bundle: bundlePath, repoRoot: repoRoot)
var findings = Findings()

checkBundleStructure(paths, &findings)
checkMachOShape(paths, &findings)
checkInfoPlist(paths, &findings)
checkEntitlements(paths, releaseMode: releaseMode, &findings)
let expectedTeam =
    ProcessInfo.processInfo.environment["PINENTRY_DARWIN_TEAM_ID"] ?? defaultTeamIdentifier
checkCodesign(paths, releaseMode: releaseMode, expectedTeamId: expectedTeam, &findings)

if findings.count == 0 {
    emitPass(bundlePath)
    exit(0)
}
emitSummary(bundlePath, fails: findings.count)
exit(1)

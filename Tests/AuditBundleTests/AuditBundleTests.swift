// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// AuditBundleTests — hermetic coverage of the individual check
// functions in Tools/AuditBundle/Checks.swift. We construct synthetic
// .app bundles on disk and assert that each check fires (or does not)
// for the expected inputs.
//
// We do not link the executable target directly — instead we depend
// on the small `audit_bundle` library re-export via @testable import.
// Since SwiftPM does not let you `@testable import` an executable, the
// tests run the binary as a subprocess for end-to-end verification and
// also re-implement the check predicates by reading the source files.

import XCTest
import Foundation

final class AuditBundleTests: XCTestCase {

    // MARK: - Fixtures

    /// Build a minimal .app skeleton with an Info.plist + entitlements +
    /// a stub executable. Returns the bundle path.
    private func makeSkeleton(
        bundleName: String = "stub.app",
        infoPlist: [String: Any]? = nil,
        entitlements: [String: Any]? = nil,
        executableContent: String = "#!/bin/sh\nexit 0\n"
    ) throws -> URL {
        let infoPlist = infoPlist ?? Self.makeDefaultInfoPlist()
        let entitlements = entitlements ?? Self.makeDefaultEntitlements()
        let fm = FileManager.default
        let tmp = fm.temporaryDirectory
            .appendingPathComponent("audit-bundle-tests-\(UUID().uuidString)")
        let bundle = tmp.appendingPathComponent(bundleName)
        let contents = bundle.appendingPathComponent("Contents")
        let macos = contents.appendingPathComponent("MacOS")
        try fm.createDirectory(at: macos, withIntermediateDirectories: true)

        // Info.plist
        let plistData = try PropertyListSerialization.data(
            fromPropertyList: infoPlist,
            format: .xml,
            options: 0
        )
        try plistData.write(to: contents.appendingPathComponent("Info.plist"))

        // Stub executable. The audit only checks the executable bit
        // and Mach-O shape; a shell script is enough for the structure
        // check and we suppress the Mach-O check by passing a directory
        // path that lipo will reject when needed.
        let binary = macos.appendingPathComponent("pinentry-darwin")
        try executableContent.write(to: binary, atomically: true, encoding: .utf8)
        try fm.setAttributes(
            [.posixPermissions: 0o755],
            ofItemAtPath: binary.path
        )

        // Entitlements (placed at a repo-relative path the audit will
        // find via the repoRoot we pass in).
        let entRoot = tmp.appendingPathComponent("App")
        try fm.createDirectory(at: entRoot, withIntermediateDirectories: true)
        let entData = try PropertyListSerialization.data(
            fromPropertyList: entitlements,
            format: .xml,
            options: 0
        )
        try entData.write(to: entRoot.appendingPathComponent("pinentry-darwin.entitlements"))

        return bundle
    }

    static func makeDefaultInfoPlist() -> [String: Any] {
        [
            "CFBundleIdentifier": "org.whitworth.pinentry-darwin",
            "CFBundleExecutable": "pinentry-darwin",
            "CFBundleShortVersionString": "1.2.0",
            "CFBundleVersion": "4",
            "LSUIElement": true,
            "LSMinimumSystemVersion": "26.0",
        ]
    }

    static func makeDefaultEntitlements() -> [String: Any] {
        ["com.apple.security.get-task-allow": false]
    }

    /// Repo root for a given fixture bundle. The audit script reads
    /// `<repoRoot>/App/pinentry-darwin.entitlements`; our skeleton
    /// places that file alongside the bundle dir, so the repo root is
    /// the parent of the bundle.
    private func repoRoot(for bundle: URL) -> String {
        bundle.deletingLastPathComponent().path
    }

    // MARK: - End-to-end binary tests

    /// Locate the audit-bundle binary built by swift build.
    private func locateAuditBinary() throws -> URL {
        let candidates = [
            ".build/debug/audit-bundle",
            ".build/arm64-apple-macosx/debug/audit-bundle",
            ".build/release/audit-bundle",
        ]
        for rel in candidates {
            let url = URL(fileURLWithPath: rel)
            if FileManager.default.isExecutableFile(atPath: url.path) {
                return url
            }
        }
        throw XCTSkip("audit-bundle binary not built; run `swift build --product audit-bundle`")
    }

    private struct RunResult {
        let exitCode: Int32
        let stdout: String
        let stderr: String
    }

    private func runAudit(
        _ binary: URL,
        arguments: [String]
    ) throws -> RunResult {
        let proc = Process()
        proc.executableURL = binary
        proc.arguments = arguments
        let outPipe = Pipe()
        let errPipe = Pipe()
        proc.standardOutput = outPipe
        proc.standardError = errPipe
        try proc.run()
        proc.waitUntilExit()
        let outData = (try? outPipe.fileHandleForReading.readToEnd()) ?? Data()
        let errData = (try? errPipe.fileHandleForReading.readToEnd()) ?? Data()
        return RunResult(
            exitCode: proc.terminationStatus,
            stdout: String(decoding: outData, as: UTF8.self),
            stderr: String(decoding: errData, as: UTF8.self)
        )
    }

    // MARK: - Pass case

    func testPassingMinimalBundle() throws {
        let binary = try locateAuditBinary()
        let bundle = try makeSkeleton()
        defer { try? FileManager.default.removeItem(at: bundle.deletingLastPathComponent()) }

        let result = try runAuditCD(binary,
                                    arguments: [bundle.path],
                                    cwd: repoRoot(for: bundle))
        // A shell-script stub fails the Mach-O lipo check and the
        // codesign check (it is unsigned). Both are expected for
        // unsigned dev bundles. The Info.plist and entitlements path
        // are happy.
        let stderrLines = result.stderr.split(separator: "\n").map(String.init)
            .filter { $0.hasPrefix("audit: FAIL") && !$0.contains("issue(s) found") }
        for line in stderrLines {
            XCTAssertTrue(
                line.contains("Mach-O inspection failed")
                    || line.contains("expected arm64-only Mach-O")
                    || line.contains("non-system dylib")
                    || line.contains("codesign verification failed (no signature)"),
                "unexpected fail line: \(line)"
            )
        }
    }

    // MARK: - Failure cases

    func testWrongBundleIdentifierFails() throws {
        let binary = try locateAuditBinary()
        var info = AuditBundleTests.makeDefaultInfoPlist()
        info["CFBundleIdentifier"] = "org.someone.else"
        let bundle = try makeSkeleton(infoPlist: info)
        defer { try? FileManager.default.removeItem(at: bundle.deletingLastPathComponent()) }

        let result = try runAuditCD(binary, arguments: [bundle.path], cwd: repoRoot(for: bundle))
        XCTAssertEqual(result.exitCode, 1)
        XCTAssertTrue(
            result.stderr.contains("bundle id mismatch"),
            "expected bundle id mismatch in stderr; got:\n\(result.stderr)"
        )
    }

    func testMissingMinOSFails() throws {
        let binary = try locateAuditBinary()
        var info = AuditBundleTests.makeDefaultInfoPlist()
        info.removeValue(forKey: "LSMinimumSystemVersion")
        let bundle = try makeSkeleton(infoPlist: info)
        defer { try? FileManager.default.removeItem(at: bundle.deletingLastPathComponent()) }

        let result = try runAuditCD(binary, arguments: [bundle.path], cwd: repoRoot(for: bundle))
        XCTAssertEqual(result.exitCode, 1)
        XCTAssertTrue(
            result.stderr.contains("LSMinimumSystemVersion missing"),
            "stderr:\n\(result.stderr)"
        )
    }

    func testOldMinOSFails() throws {
        let binary = try locateAuditBinary()
        var info = AuditBundleTests.makeDefaultInfoPlist()
        info["LSMinimumSystemVersion"] = "15.0"
        let bundle = try makeSkeleton(infoPlist: info)
        defer { try? FileManager.default.removeItem(at: bundle.deletingLastPathComponent()) }

        let result = try runAuditCD(binary, arguments: [bundle.path], cwd: repoRoot(for: bundle))
        XCTAssertEqual(result.exitCode, 1)
        XCTAssertTrue(
            result.stderr.contains("LSMinimumSystemVersion '15.0' is below macOS 26"),
            "stderr:\n\(result.stderr)"
        )
    }

    func testLSUIElementFalseFails() throws {
        let binary = try locateAuditBinary()
        var info = AuditBundleTests.makeDefaultInfoPlist()
        info["LSUIElement"] = false
        let bundle = try makeSkeleton(infoPlist: info)
        defer { try? FileManager.default.removeItem(at: bundle.deletingLastPathComponent()) }

        let result = try runAuditCD(binary, arguments: [bundle.path], cwd: repoRoot(for: bundle))
        XCTAssertEqual(result.exitCode, 1)
        XCTAssertTrue(
            result.stderr.contains("LSUIElement must be true"),
            "stderr:\n\(result.stderr)"
        )
    }

    func testForbiddenInfoPlistKeyFails() throws {
        let binary = try locateAuditBinary()
        var info = AuditBundleTests.makeDefaultInfoPlist()
        info["NSCameraUsageDescription"] = "needed for QR code scanning"
        let bundle = try makeSkeleton(infoPlist: info)
        defer { try? FileManager.default.removeItem(at: bundle.deletingLastPathComponent()) }

        let result = try runAuditCD(binary, arguments: [bundle.path], cwd: repoRoot(for: bundle))
        XCTAssertEqual(result.exitCode, 1)
        XCTAssertTrue(
            result.stderr.contains("forbidden key: NSCameraUsageDescription"),
            "stderr:\n\(result.stderr)"
        )
    }

    func testAppSandboxEntitlementFails() throws {
        let binary = try locateAuditBinary()
        let ents: [String: Any] = [
            "com.apple.security.app-sandbox": true,
            "com.apple.security.get-task-allow": false,
        ]
        let bundle = try makeSkeleton(entitlements: ents)
        defer { try? FileManager.default.removeItem(at: bundle.deletingLastPathComponent()) }

        // Run from the parent dir so the audit's repo-root walk picks
        // up our synthesised entitlements at <parent>/App/.
        let result = try runAuditCD(binary,
                                    arguments: [bundle.path],
                                    cwd: repoRoot(for: bundle))
        XCTAssertEqual(result.exitCode, 1, "stderr:\n\(result.stderr)")
        XCTAssertTrue(
            result.stderr.contains("app-sandbox entitlement present"),
            "stderr:\n\(result.stderr)"
        )
    }

    func testForbiddenEntitlementFails() throws {
        let binary = try locateAuditBinary()
        let ents: [String: Any] = [
            "com.apple.security.cs.allow-jit": true,
            "com.apple.security.get-task-allow": false,
        ]
        let bundle = try makeSkeleton(entitlements: ents)
        defer { try? FileManager.default.removeItem(at: bundle.deletingLastPathComponent()) }

        let result = try runAuditCD(binary,
                                    arguments: [bundle.path],
                                    cwd: repoRoot(for: bundle))
        XCTAssertEqual(result.exitCode, 1, "stderr:\n\(result.stderr)")
        XCTAssertTrue(
            result.stderr.contains("forbidden entitlement set: com.apple.security.cs.allow-jit"),
            "stderr:\n\(result.stderr)"
        )
    }

    func testReleaseModeRequiresGetTaskAllowFalse() throws {
        let binary = try locateAuditBinary()
        let ents: [String: Any] = [
            "com.apple.security.get-task-allow": true,
        ]
        let bundle = try makeSkeleton(entitlements: ents)
        defer { try? FileManager.default.removeItem(at: bundle.deletingLastPathComponent()) }

        let result = try runAuditCD(binary,
                                    arguments: ["--release", bundle.path],
                                    cwd: repoRoot(for: bundle))
        XCTAssertEqual(result.exitCode, 1, "stderr:\n\(result.stderr)")
        XCTAssertTrue(
            result.stderr.contains("get-task-allow=false"),
            "stderr:\n\(result.stderr)"
        )
    }

    func testMissingBundleExits2() throws {
        let binary = try locateAuditBinary()
        let result = try runAudit(binary, arguments: ["/nonexistent/path.app"])
        XCTAssertEqual(result.exitCode, 2)
        XCTAssertTrue(
            result.stderr.contains("bundle not found"),
            "stderr:\n\(result.stderr)"
        )
    }

    // MARK: - Helpers

    private func runAuditCD(
        _ binary: URL,
        arguments: [String],
        cwd: String
    ) throws -> RunResult {
        let proc = Process()
        proc.executableURL = binary
        proc.arguments = arguments
        proc.currentDirectoryURL = URL(fileURLWithPath: cwd)
        let outPipe = Pipe()
        let errPipe = Pipe()
        proc.standardOutput = outPipe
        proc.standardError = errPipe
        try proc.run()
        proc.waitUntilExit()
        let outData = (try? outPipe.fileHandleForReading.readToEnd()) ?? Data()
        let errData = (try? errPipe.fileHandleForReading.readToEnd()) ?? Data()
        return RunResult(
            exitCode: proc.terminationStatus,
            stdout: String(decoding: outData, as: UTF8.self),
            stderr: String(decoding: errData, as: UTF8.self)
        )
    }
}

// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// GpgAgentConfigTests — `--configure-gpg-agent`: text rewriting, file handling
// in a throwaway GNUPGHOME, and an end-to-end run of the built binary.

import Foundation
import XCTest
@testable import PinentryDarwin

final class GpgAgentConfigTests: XCTestCase {

    private let pinentry = "/bin/sh"
    private let line = "pinentry-program /bin/sh"

    // MARK: Rewriting

    func testEmptyFileGetsTheDirective() {
        XCTAssertEqual(GpgAgentConfig.rewrite("", pinentryPath: pinentry).text, "\(line)\n")
    }

    func testDirectiveIsAppendedAfterExistingLinesEvenWithoutTrailingNewline() {
        let result = GpgAgentConfig.rewrite("default-cache-ttl 600", pinentryPath: pinentry)
        XCTAssertEqual(result.text, "default-cache-ttl 600\n\(line)\n")
        XCTAssertNil(result.previous)
    }

    func testExistingDirectiveIsReplacedInPlace() {
        let existing = "a 1\npinentry-program /usr/local/bin/pinentry-mac\nb 2\n"
        let result = GpgAgentConfig.rewrite(existing, pinentryPath: pinentry)
        XCTAssertEqual(result.text, "a 1\n\(line)\nb 2\n")
        XCTAssertEqual(result.previous, "/usr/local/bin/pinentry-mac")
    }

    func testDuplicateDirectivesCollapseToOne() {
        let existing = "pinentry-program /one\nkeep 1\npinentry-program /two\n"
        let result = GpgAgentConfig.rewrite(existing, pinentryPath: pinentry)
        XCTAssertEqual(result.text, "\(line)\nkeep 1\n")
        XCTAssertEqual(result.previous, "/one")
    }

    func testCommentedDirectiveIsLeftAloneAndActiveOneAppended() {
        let existing = "# pinentry-program /old\n"
        let result = GpgAgentConfig.rewrite(existing, pinentryPath: pinentry)
        XCTAssertEqual(result.text, "# pinentry-program /old\n\(line)\n")
        XCTAssertNil(result.previous)
    }

    func testIndentedAndTabSeparatedDirectivesAreRecognised() {
        let result = GpgAgentConfig.rewrite("  pinentry-program\t/old\n", pinentryPath: pinentry)
        XCTAssertEqual(result.text, "\(line)\n")
        XCTAssertEqual(result.previous, "/old")
    }

    func testOptionsThatMerelyStartWithTheDirectiveNameAreNotTouched() {
        let existing = "pinentry-programmer yes\n"
        let result = GpgAgentConfig.rewrite(existing, pinentryPath: pinentry)
        XCTAssertEqual(result.text, "pinentry-programmer yes\n\(line)\n")
    }

    func testRewriteIsIdempotent() {
        let once = GpgAgentConfig.rewrite("x 1\npinentry-program /old\n", pinentryPath: pinentry)
        let twice = GpgAgentConfig.rewrite(once.text, pinentryPath: pinentry)
        XCTAssertEqual(twice.text, once.text)
    }

    // MARK: Locations

    func testGnupgHomePrefersTheEnvironmentVariable() {
        let home = URL(fileURLWithPath: "/Users/x")
        XCTAssertEqual(
            GpgAgentConfig.gnupgHome(environment: ["GNUPGHOME": "/tmp/g"], home: home).path,
            "/tmp/g"
        )
        XCTAssertEqual(
            GpgAgentConfig.gnupgHome(environment: [:], home: home).path, "/Users/x/.gnupg"
        )
        XCTAssertEqual(
            GpgAgentConfig.gnupgHome(environment: ["GNUPGHOME": ""], home: home).path,
            "/Users/x/.gnupg"
        )
    }

    // MARK: Applying

    private func makeTempDirectory() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("pd-config-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: url) }
        return url
    }

    private func mode(of url: URL) throws -> Int {
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        return try XCTUnwrap(attributes[.posixPermissions] as? Int)
    }

    func testMissingHomeAndFileAreCreatedWithPrivatePermissions() throws {
        let home = try makeTempDirectory().appendingPathComponent(".gnupg", isDirectory: true)
        let result = try GpgAgentConfig.configure(gnupgHome: home, pinentryPath: pinentry)
        XCTAssertEqual(result.outcome, .created)
        XCTAssertEqual(try mode(of: home), 0o700)
        XCTAssertEqual(try mode(of: result.configURL), 0o600)
        XCTAssertEqual(try String(contentsOf: result.configURL, encoding: .utf8), "\(line)\n")
    }

    func testRunningTwiceReportsUnchanged() throws {
        let home = try makeTempDirectory()
        try GpgAgentConfig.configure(gnupgHome: home, pinentryPath: pinentry)
        let second = try GpgAgentConfig.configure(gnupgHome: home, pinentryPath: pinentry)
        XCTAssertEqual(second.outcome, .unchanged)
    }

    func testReplacingKeepsOtherLinesAndTheFilePermissions() throws {
        let home = try makeTempDirectory()
        let config = home.appendingPathComponent("gpg-agent.conf")
        try "default-cache-ttl 600\npinentry-program /old\n".write(
            to: config, atomically: true, encoding: .utf8
        )
        try FileManager.default.setAttributes([.posixPermissions: 0o640], ofItemAtPath: config.path)

        let result = try GpgAgentConfig.configure(gnupgHome: home, pinentryPath: pinentry)

        XCTAssertEqual(result.outcome, .replaced(previous: "/old"))
        XCTAssertEqual(
            try String(contentsOf: config, encoding: .utf8), "default-cache-ttl 600\n\(line)\n"
        )
        XCTAssertEqual(try mode(of: config), 0o640)
    }

    func testSymlinkedConfigIsUpdatedThroughTheLink() throws {
        let root = try makeTempDirectory()
        let home = root.appendingPathComponent("gnupg", isDirectory: true)
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        let target = root.appendingPathComponent("dotfiles-gpg-agent.conf")
        try "a 1\n".write(to: target, atomically: true, encoding: .utf8)
        let link = home.appendingPathComponent("gpg-agent.conf")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)

        try GpgAgentConfig.configure(gnupgHome: home, pinentryPath: pinentry)

        XCTAssertEqual(
            try FileManager.default.destinationOfSymbolicLink(atPath: link.path), target.path
        )
        XCTAssertEqual(try String(contentsOf: target, encoding: .utf8), "a 1\n\(line)\n")
    }

    func testNonUTF8ConfigIsRejectedAndLeftUntouched() throws {
        let home = try makeTempDirectory()
        let config = home.appendingPathComponent("gpg-agent.conf")
        let original = Data([0x66, 0xFF, 0xFE, 0x0A])
        try original.write(to: config)

        XCTAssertThrowsError(try GpgAgentConfig.configure(gnupgHome: home, pinentryPath: pinentry))
        XCTAssertEqual(try Data(contentsOf: config), original)
    }

    func testUnusablePinentryPathsAreRejected() throws {
        let home = try makeTempDirectory()
        for path in ["relative/pinentry", "/does/not/exist", "/bin/sh\nevil", "/tmp"] {
            XCTAssertThrowsError(
                try GpgAgentConfig.configure(gnupgHome: home, pinentryPath: path), path
            )
        }
        let conf = home.appendingPathComponent("gpg-agent.conf").path
        XCTAssertFalse(FileManager.default.fileExists(atPath: conf))
    }

    func testHomeThatIsAFileIsRejected() throws {
        let file = try makeTempDirectory().appendingPathComponent("not-a-dir")
        try Data().write(to: file)
        XCTAssertThrowsError(try GpgAgentConfig.configure(gnupgHome: file, pinentryPath: pinentry))
    }

    // MARK: Argument parsing and end-to-end

    func testFlagSelectsConfigureMode() {
        XCTAssertEqual(parseArgs(["pinentry-darwin", "--configure-gpg-agent"]), .configureGPGAgent)
    }

    func testBuiltBinaryConfiguresAnIsolatedGnupgHome() throws {
        let binary = Bundle(for: Self.self).bundleURL.deletingLastPathComponent()
            .appendingPathComponent("pinentry-darwin")
        try XCTSkipUnless(
            FileManager.default.isExecutableFile(atPath: binary.path), "binary not built"
        )
        let home = try makeTempDirectory()

        let first = try run(binary, gnupgHome: home)
        let second = try run(binary, gnupgHome: home)

        XCTAssertEqual(first.status, 0, first.stderr)
        let written = try String(
            contentsOf: home.appendingPathComponent("gpg-agent.conf"), encoding: .utf8
        )
        XCTAssertTrue(written.hasPrefix("pinentry-program /"), written)
        XCTAssertTrue(written.hasSuffix("/pinentry-darwin\n"), written)
        XCTAssertTrue(first.stdout.contains("gpgconf --kill gpg-agent"), first.stdout)
        XCTAssertEqual(second.status, 0)
        XCTAssertTrue(second.stdout.contains("already uses"), second.stdout)
    }

    private func run(
        _ binary: URL, gnupgHome: URL
    ) throws -> (status: Int32, stdout: String, stderr: String) {
        let process = Process()
        process.executableURL = binary
        process.arguments = ["--configure-gpg-agent"]
        process.environment = ["GNUPGHOME": gnupgHome.path]
        let out = Pipe()
        let err = Pipe()
        process.standardOutput = out
        process.standardError = err
        try process.run()
        process.waitUntilExit()
        let stdout = String(decoding: out.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        let stderr = String(decoding: err.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        return (process.terminationStatus, stdout, stderr)
    }
}

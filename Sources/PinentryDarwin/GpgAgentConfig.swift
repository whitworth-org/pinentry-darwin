// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// GpgAgentConfig.swift — `pinentry-darwin --configure-gpg-agent`: make
// gpg-agent, and therefore gpg, pass and git, launch this binary for
// passphrase prompts by setting `pinentry-program` in gpg-agent.conf.

import Foundation

enum GpgAgentConfig {

    enum Outcome: Equatable {
        case created
        case added
        case replaced(previous: String)
        case unchanged
    }

    struct ConfigError: Error, CustomStringConvertible, Equatable {
        let description: String
    }

    static let directive = "pinentry-program"

    // MARK: - Pure text rewriting

    /// Return `existing` with exactly one active `pinentry-program` line set to
    /// `path`. The first active line is replaced in place, later duplicates are
    /// dropped, commented-out and unrelated lines are untouched, and a line is
    /// appended when none exists. `previous` is the replaced value, if any.
    static func rewrite(
        _ existing: String, pinentryPath path: String
    ) -> (text: String, previous: String?) {
        let newLine = "\(directive) \(path)"
        var previous: String?
        var output: [String] = []
        for line in existing.components(separatedBy: "\n") {
            guard let value = activeValue(of: line) else {
                output.append(line)
                continue
            }
            if previous == nil {
                previous = value
                output.append(newLine)
            }
        }
        if previous == nil {
            if output.last == "" { output.removeLast() }
            output.append(newLine)
        }
        var text = output.joined(separator: "\n")
        if !text.hasSuffix("\n") { text += "\n" }
        return (text, previous)
    }

    /// The value of an active (not commented) `pinentry-program` line, else nil.
    private static func activeValue(of line: String) -> String? {
        let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.hasPrefix(directive) else { return nil }
        let rest = trimmed.dropFirst(directive.count)
        if rest.isEmpty { return "" }
        guard let first = rest.first, first == " " || first == "\t" else { return nil }
        return rest.trimmingCharacters(in: .whitespaces)
    }

    // MARK: - Locations

    /// `$GNUPGHOME` when set, otherwise `~/.gnupg`.
    static func gnupgHome(environment: [String: String], home: URL) -> URL {
        if let custom = environment["GNUPGHOME"], !custom.isEmpty {
            return URL(fileURLWithPath: custom, isDirectory: true)
        }
        return home.appendingPathComponent(".gnupg", isDirectory: true)
    }

    // MARK: - Applying

    /// Point `<gnupgHome>/gpg-agent.conf` at `pinentryPath`. Creates the
    /// directory (0700) and file (0600) when missing, follows a symlinked
    /// config so dotfile managers keep working, preserves an existing file's
    /// permissions, and replaces the file atomically.
    @discardableResult
    static func configure(
        gnupgHome: URL, pinentryPath: String, fileManager: FileManager = .default
    ) throws -> (outcome: Outcome, configURL: URL) {
        try validate(pinentryPath: pinentryPath, fileManager: fileManager)
        try ensureDirectory(gnupgHome, fileManager: fileManager)

        let configURL = gnupgHome.appendingPathComponent("gpg-agent.conf")
            .resolvingSymlinksInPath()
        let existing = try readExisting(configURL, fileManager: fileManager)
        let (text, previous) = rewrite(existing ?? "", pinentryPath: pinentryPath)

        if text == existing { return (.unchanged, configURL) }
        let mode = try existing == nil ? 0o600 : permissions(of: configURL, fileManager)
        try writeAtomically(text, to: configURL, mode: mode, fileManager: fileManager)

        switch (existing, previous) {
        case (nil, _): return (.created, configURL)
        case (_, nil): return (.added, configURL)
        case (_, let old?): return (.replaced(previous: old), configURL)
        }
    }

    private static func validate(pinentryPath path: String, fileManager: FileManager) throws {
        guard path.hasPrefix("/") else {
            throw ConfigError(description: "pinentry path '\(path)' is not absolute")
        }
        guard !path.contains(where: { $0 == "\n" || $0 == "\r" || $0 == "\0" }) else {
            throw ConfigError(description: "pinentry path contains a control character")
        }
        let resolved = URL(fileURLWithPath: path).resolvingSymlinksInPath()
        let isRegularFile = (try? resolved.resourceValues(forKeys: [.isRegularFileKey]))?
            .isRegularFile == true
        guard isRegularFile, fileManager.isExecutableFile(atPath: path) else {
            throw ConfigError(description: "pinentry path '\(path)' is not an executable file")
        }
    }

    private static func ensureDirectory(_ url: URL, fileManager: FileManager) throws {
        var isDirectory: ObjCBool = false
        if unsafe fileManager.fileExists(atPath: url.path, isDirectory: &isDirectory) {
            guard isDirectory.boolValue else {
                throw ConfigError(description: "'\(url.path)' exists but is not a directory")
            }
            return
        }
        do {
            try fileManager.createDirectory(
                at: url, withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
        } catch {
            throw ConfigError(
                description: "cannot create '\(url.path)': \(error.localizedDescription)"
            )
        }
    }

    private static func readExisting(_ url: URL, fileManager: FileManager) throws -> String? {
        guard fileManager.fileExists(atPath: url.path) else { return nil }
        do {
            return try String(contentsOf: url, encoding: .utf8)
        } catch {
            throw ConfigError(
                description: "cannot read '\(url.path)' as UTF-8 text; left unchanged"
            )
        }
    }

    private static func permissions(of url: URL, _ fileManager: FileManager) throws -> Int {
        let attributes = try fileManager.attributesOfItem(atPath: url.path)
        return (attributes[.posixPermissions] as? Int) ?? 0o600
    }

    private static func writeAtomically(
        _ text: String, to url: URL, mode: Int, fileManager: FileManager
    ) throws {
        let temp = url.deletingLastPathComponent()
            .appendingPathComponent(".gpg-agent.conf.\(UUID().uuidString)")
        guard fileManager.createFile(
            atPath: temp.path, contents: Data(text.utf8), attributes: [.posixPermissions: mode]
        ) else {
            throw ConfigError(description: "cannot write '\(temp.path)'")
        }
        do {
            if fileManager.fileExists(atPath: url.path) {
                _ = try fileManager.replaceItemAt(url, withItemAt: temp)
            } else {
                try fileManager.moveItem(at: temp, to: url)
            }
        } catch {
            try? fileManager.removeItem(at: temp)
            throw ConfigError(
                description: "cannot update '\(url.path)': \(error.localizedDescription)"
            )
        }
    }

    // MARK: - Command

    /// Run `--configure-gpg-agent`; returns the process exit status.
    static func run(
        environment: [String: String] = ProcessInfo.processInfo.environment,
        executablePath: String? = Bundle.main.executablePath
    ) -> Int32 {
        guard let executablePath else {
            return fail("cannot determine the path of this executable")
        }
        let home = gnupgHome(
            environment: environment, home: FileManager.default.homeDirectoryForCurrentUser
        )
        do {
            let (outcome, configURL) = try configure(gnupgHome: home, pinentryPath: executablePath)
            print(message(for: outcome, configPath: configURL.path, pinentryPath: executablePath))
            print("Restart the agent to apply it: gpgconf --kill gpg-agent")
            return 0
        } catch {
            return fail("\(error)")
        }
    }

    static func message(for outcome: Outcome, configPath: String, pinentryPath: String) -> String {
        switch outcome {
        case .created, .added:
            return "Set pinentry-program to \(pinentryPath) in \(configPath)."
        case .replaced(let previous):
            return "Replaced pinentry-program \(previous) with \(pinentryPath) in \(configPath)."
        case .unchanged:
            return "\(configPath) already uses \(pinentryPath)."
        }
    }

    private static func fail(_ reason: String) -> Int32 {
        let line = "pinentry-darwin: --configure-gpg-agent failed: \(reason)\n"
        try? FileHandle.standardError.write(contentsOf: Data(line.utf8))
        return 1
    }
}

// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// Checks.swift — the individual audit predicates, factored out of
// `main.swift` so each one is independently unit-testable.
//
// Each `check*` function takes a `Findings` struct (passed inout) and
// appends `audit: FAIL — <reason>` lines for any violation. The
// caller's exit code is determined by `findings.count` at the end.
//
// We mirror `scripts/audit-bundle.sh` line-for-line; future divergence
// must be explicit, since the legacy script is the regression baseline.

import Foundation

// MARK: - Bundle paths

/// Resolved paths derived from the bundle root. Computed once per
/// invocation.
public struct BundlePaths {
    public let bundle: String
    public let binary: String
    public let infoPlist: String
    public let entitlementsSrc: String

    public init(bundle: String, repoRoot: String) {
        self.bundle = bundle
        self.binary = bundle + "/Contents/MacOS/pinentry-darwin"
        self.infoPlist = bundle + "/Contents/Info.plist"
        self.entitlementsSrc = repoRoot + "/App/pinentry-darwin.entitlements"
    }
}

// MARK: - Bundle structure

public func checkBundleStructure(_ paths: BundlePaths, _ findings: inout Findings) {
    let fm = FileManager.default
    if !fm.isExecutableFile(atPath: paths.binary) {
        findings.fail("missing executable: \(paths.binary)")
    }
    if !fm.fileExists(atPath: paths.infoPlist) {
        findings.fail("missing Info.plist")
    }
    if !fm.fileExists(atPath: paths.entitlementsSrc) {
        findings.fail("missing source entitlements: \(paths.entitlementsSrc)")
    }
}

// MARK: - Mach-O shape

public func checkMachOShape(_ paths: BundlePaths, _ findings: inout Findings) {
    let fm = FileManager.default
    guard fm.isExecutableFile(atPath: paths.binary) else { return }

    do {
        let archResult = try runProcess("/usr/bin/lipo", ["-archs", paths.binary])
        let archs = archResult.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        if archs != "arm64" {
            findings.fail("expected arm64-only Mach-O, got: \(archs)")
        }

        // otool -L lists linked dylibs. Skip the first line (the file
        // header) and any line whose first whitespace-token does not
        // begin with '/' (compatibility / current version notations).
        let otoolResult = try runProcess("/usr/bin/otool", ["-L", paths.binary])
        let lines = otoolResult.stdout.split(separator: "\n", omittingEmptySubsequences: true)
        for line in lines.dropFirst() {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard let firstToken = trimmed.split(separator: " ", maxSplits: 1).first else { continue }
            let dep = String(firstToken)
            guard dep.hasPrefix("/") else { continue }
            if !dep.hasPrefix("/usr/lib/") && !dep.hasPrefix("/System/Library/") {
                findings.fail("non-system dylib linked: \(dep)")
            }
        }
    } catch {
        findings.fail("Mach-O inspection failed: \(error)")
    }
}

// MARK: - Info.plist invariants

public func checkInfoPlist(_ paths: BundlePaths, _ findings: inout Findings) {
    let fm = FileManager.default
    guard fm.fileExists(atPath: paths.infoPlist) else { return }

    let plist: [String: Any]
    do {
        let url = URL(fileURLWithPath: paths.infoPlist)
        let data = try Data(contentsOf: url)
        let raw = try PropertyListSerialization.propertyList(from: data, format: nil)
        guard let dict = raw as? [String: Any] else {
            findings.fail("Info.plist root is not a dictionary")
            return
        }
        plist = dict
    } catch {
        findings.fail("Info.plist parse failed: \(error)")
        return
    }

    let bundleId = plist["CFBundleIdentifier"] as? String ?? ""
    if bundleId != "org.whitworth.pinentry-darwin" {
        findings.fail("bundle id mismatch: '\(bundleId)' (want org.whitworth.pinentry-darwin)")
    }

    let shortVer = plist["CFBundleShortVersionString"] as? String ?? ""
    if shortVer.isEmpty {
        findings.fail("CFBundleShortVersionString missing")
    }

    // LSUIElement: PropertyListSerialization decodes <true/>/<false/>
    // as Bool, and the older YES/NO/1/0 spellings as Bool too via the
    // plist format itself. We treat anything truthy as pass.
    if let uiElement = plist["LSUIElement"] as? Bool {
        if !uiElement {
            findings.fail("LSUIElement must be true (no Dock icon for Assuan agent mode)")
        }
    } else if let uiInt = plist["LSUIElement"] as? Int {
        if uiInt == 0 {
            findings.fail("LSUIElement must be true (no Dock icon for Assuan agent mode)")
        }
    } else if let uiStr = plist["LSUIElement"] as? String {
        let lower = uiStr.lowercased()
        let truthy: Set<String> = ["true", "yes", "1"]
        if !truthy.contains(lower) {
            findings.fail("LSUIElement must be true (no Dock icon for Assuan agent mode); got '\(uiStr)'")
        }
    } else {
        findings.fail("LSUIElement must be true (no Dock icon for Assuan agent mode)")
    }

    let minOS = plist["LSMinimumSystemVersion"] as? String ?? ""
    if minOS.isEmpty {
        findings.fail("LSMinimumSystemVersion missing (require 26.0+ for SE-SSH)")
    } else if !isMinOSAtLeast26(minOS) {
        findings.fail("LSMinimumSystemVersion '\(minOS)' is below macOS 26 (require 26.0+ for SE-SSH)")
    }

    let forbiddenKeys = [
        "CFBundleURLTypes",
        "LSEnvironment",
        "NSAppleEventsUsageDescription",
        "NSCameraUsageDescription",
        "NSMicrophoneUsageDescription",
        "NSContactsUsageDescription",
        "NSLocationUsageDescription",
        "NSCalendarsUsageDescription",
        "NSRemindersUsageDescription",
        "NSSystemAdministrationUsageDescription",
        "NSPhotoLibraryUsageDescription",
        "SUFeedURL",
    ]
    for key in forbiddenKeys where plist[key] != nil {
        findings.fail("Info.plist contains forbidden key: \(key)")
    }
}

/// Major component must be 26 or higher. Forward-compatible through
/// any major bump the OS introduces.
func isMinOSAtLeast26(_ value: String) -> Bool {
    let parts = value.split(separator: ".")
    guard let majorStr = parts.first, let major = Int(majorStr) else { return false }
    return major >= 26
}

// MARK: - Entitlements

public func checkEntitlements(
    _ paths: BundlePaths,
    releaseMode: Bool,
    _ findings: inout Findings
) {
    let plist = loadEntitlements(paths)
    guard let plist else { return }

    // app-sandbox must be absent / not true — sandbox breaks
    // gpg-agent stdio inheritance.
    if isEntitlementTrue(plist, key: "com.apple.security.app-sandbox") {
        findings.fail("app-sandbox entitlement present — must be absent (breaks gpg-agent stdio)")
    }

    if releaseMode {
        // get-task-allow must be present and false.
        if let value = plist["com.apple.security.get-task-allow"] {
            if !isFalse(value) {
                findings.fail("release requires com.apple.security.get-task-allow=false (got '\(value)')")
            }
        } else {
            findings.fail("release requires com.apple.security.get-task-allow=false (got 'absent')")
        }
    }

    let forbidden = [
        "com.apple.security.cs.allow-jit",
        "com.apple.security.cs.allow-unsigned-executable-memory",
        "com.apple.security.cs.disable-library-validation",
        "com.apple.security.cs.allow-dyld-environment-variables",
        "com.apple.security.cs.disable-executable-page-protection",
        "com.apple.security.cs.debugger",
        "com.apple.security.cs.allow-relative-library-loads",
        "com.apple.security.network.client",
        "com.apple.security.network.server",
        "com.apple.security.device.camera",
        "com.apple.security.device.microphone",
        "com.apple.security.device.usb",
        "com.apple.security.device.audio-input",
        "com.apple.security.personal-information.contacts",
        "com.apple.security.personal-information.photos-library",
        "com.apple.security.personal-information.calendars",
        "com.apple.security.personal-information.reminders",
        "com.apple.security.personal-information.location",
        "com.apple.security.automation.apple-events",
    ]
    for key in forbidden where isEntitlementTrue(plist, key: key) {
        findings.fail("forbidden entitlement set: \(key)")
    }
}

/// Load entitlements: prefer the signature-embedded copy; fall back
/// to the repo-source file for unsigned dev builds. Returns nil if
/// neither is available, in which case the caller silently no-ops.
func loadEntitlements(_ paths: BundlePaths) -> [String: Any]? {
    // Try codesign-embedded first.
    if let embedded = try? runProcess(
        "/usr/bin/codesign",
        ["-d", "--entitlements", "-", "--xml", paths.bundle]
    ), embedded.didSucceed, !embedded.stdout.isEmpty,
       let data = embedded.stdout.data(using: .utf8),
       let raw = try? PropertyListSerialization.propertyList(from: data, format: nil),
       let dict = raw as? [String: Any] {
        return dict
    }
    // Fall back to repo source.
    let url = URL(fileURLWithPath: paths.entitlementsSrc)
    guard let data = try? Data(contentsOf: url),
          let raw = try? PropertyListSerialization.propertyList(from: data, format: nil),
          let dict = raw as? [String: Any] else {
        return nil
    }
    return dict
}

func isEntitlementTrue(_ plist: [String: Any], key: String) -> Bool {
    guard let value = plist[key] else { return false }
    if let b = value as? Bool { return b }
    if let i = value as? Int { return i != 0 }
    if let s = value as? String {
        let lower = s.lowercased()
        return lower == "true" || lower == "yes" || lower == "1"
    }
    return false
}

func isFalse(_ value: Any) -> Bool {
    if let b = value as? Bool { return !b }
    if let i = value as? Int { return i == 0 }
    if let s = value as? String {
        let lower = s.lowercased()
        return lower == "false" || lower == "no" || lower == "0"
    }
    return false
}

// MARK: - Codesign

public func checkCodesign(
    _ paths: BundlePaths,
    releaseMode: Bool,
    expectedTeamId: String,
    _ findings: inout Findings
) {
    let fm = FileManager.default
    guard fm.isExecutableFile(atPath: paths.binary) else { return }

    let verifyResult: ProcRunResult
    do {
        verifyResult = try runProcess("/usr/bin/codesign", ["-dv", paths.bundle])
    } catch {
        findings.fail("codesign verification failed (\(error))")
        return
    }
    if !verifyResult.didSucceed {
        findings.fail("codesign verification failed (no signature)")
        return
    }

    let dumpResult: ProcRunResult
    do {
        dumpResult = try runProcess("/usr/bin/codesign", ["-dv", "--verbose=2", paths.bundle])
    } catch {
        findings.fail("codesign --verbose dump failed (\(error))")
        return
    }
    let dump = dumpResult.stdout + "\n" + dumpResult.stderr
    let flags = codesignFlags(in: dump)
    if !flags.contains("runtime") {
        if releaseMode {
            findings.fail("hardened runtime not set (codesign flags: \(flags))")
        }
    }

    if releaseMode {
        if !dump.split(separator: "\n").contains(where: { line in
            line.hasPrefix("Authority=Developer ID Application:")
        }) {
            findings.fail("release mode requires Developer ID Application signature")
        }
        if !dump.split(separator: "\n").contains(where: { line in
            line.hasPrefix("Timestamp=")
        }) {
            findings.fail("release mode requires --timestamp signature (notarytool will reject without)")
        }
        do {
            let stapler = try runProcess("/usr/bin/xcrun", ["stapler", "validate", paths.bundle])
            if !stapler.didSucceed {
                findings.fail("release mode requires stapled notarization")
            }
        } catch {
            findings.fail("stapler validate failed (\(error))")
        }
        if !dump.contains("TeamIdentifier=\(expectedTeamId)") {
            let actual = extractTeamId(from: dump) ?? ""
            findings.fail("release TeamIdentifier mismatch: expected '\(expectedTeamId)', got '\(actual)'")
        }
    }
}

func codesignFlags(in dump: String) -> String {
    for line in dump.split(separator: "\n", omittingEmptySubsequences: true) {
        let s = String(line)
        guard s.hasPrefix("CodeDirectory v=") else { continue }
        if let range = s.range(of: "flags=") {
            let rest = s[range.upperBound...]
            if let end = rest.firstIndex(of: " ") {
                return String(rest[..<end])
            }
            return String(rest)
        }
    }
    return ""
}

func extractTeamId(from dump: String) -> String? {
    for line in dump.split(separator: "\n", omittingEmptySubsequences: true) {
        let s = String(line)
        if s.hasPrefix("TeamIdentifier=") {
            return String(s.dropFirst("TeamIdentifier=".count))
        }
    }
    return nil
}

// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// SettingsRenderTests — renders each Settings tab headlessly in Light and
// Dark with mock data (never the real Keychain, sc_auth, or ssh-add). The
// windows are never shown. Set PINENTRY_RENDER_DIR to also save PNGs.

import AppKit
import KeychainStore
import SwiftUI
import SSHIdentity
import XCTest
@testable import PinentryUI

// MARK: - Mock SSH clients

private struct StubSCAuth: SCAuthClientProtocol {
    var identities: [CTKIdentity] = []
    var partial: CTKIdentityListing.PartialReason?
    var failure: SCAuthError?
    var hangs = false

    func listIdentities() async throws -> CTKIdentityListing {
        if hangs { try await Task.sleep(for: .seconds(60)) }
        if let failure { throw failure }
        return CTKIdentityListing(identities: identities, partial: partial)
    }

    func createIdentity(label: String) async throws {}
    func deleteIdentity(publicKeyHash: String) async throws {}
}

private struct StubSSHAdd: SSHAddClientProtocol {
    var keys: [SSHAgentKey] = []

    func registerSecurityKeyProvider() async throws {}
    func listAgentIdentities() async throws -> [SSHAgentKey] { keys }
}

private enum Fixtures {
    static let fingerprints = [
        "9F3A1C7E5B2D40869AC1E3B7D5F20184C6A9E37B",
        "1D4B8F20A6C3957E0B2F6D81C4A7E5390F1B2C6D",
        "C07E9A31F58D2B64E1A09C3D7F5B8E2461A0D93C",
    ]

    static let identities = [
        CTKIdentity(
            keyType: .p256NE,
            publicKeyHash: "3B5C1E8A94D7F20613AC5E9B7D40F8216CA3E5D9",
            sshFingerprint: "SHA256:k3Q8xV1nT7mYb2PzR0cFhJ5wLd9aUe4oGsXiN6tBqMA",
            protection: .bio,
            label: "ssh-laptop",
            commonName: "ssh-laptop",
            emailAddress: "",
            validToRaw: "07.10.27, 09:14",
            isValid: true
        ),
        CTKIdentity(
            keyType: .p256NE,
            publicKeyHash: "A7D2F4098C1B5E3640DA9F7C2B8E5136D4A0C9F1",
            sshFingerprint: "SHA256:Zp0LwQe7Yt3NdK8vR5hJb2cXaUg9oFsMiT4nBqE1xVA",
            protection: .bio,
            label: "ssh-ci",
            commonName: "ssh-ci",
            emailAddress: "",
            validToRaw: "03.02.26, 11:30",
            isValid: false
        ),
        CTKIdentity(
            keyType: nil,
            publicKeyHash: "5E9A3C7B1D8F4206A3C5E7B9D1F08246CA3E5B79",
            sshFingerprint: nil,
            protection: .none,
            label: "ssh-bench",
            commonName: "ssh-bench",
            emailAddress: "",
            validToRaw: "",
            isValid: true
        ),
    ]

    static let agentKeys = [
        SSHAgentKey(
            keyType: "sk-ecdsa-sha2-nistp256@openssh.com",
            base64Blob: "AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTY",
            comment: "ssh-laptop",
            rawLine: "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZA"
                + "b3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBHk3Q8xV1nT7mYb2PzR0cFhJ5wLd9a ssh-laptop"
        ),
    ]
}

// MARK: - Tests

@MainActor
final class SettingsRenderTests: XCTestCase {

    private var outputDir: URL? {
        ProcessInfo.processInfo.environment["PINENTRY_RENDER_DIR"].map { URL(filePath: $0) }
    }

    private func makeStore() -> KeyPolicyStore {
        let suite = "SettingsRenderTests.\(UUID().uuidString)"
        addTeardownBlock { UserDefaults(suiteName: suite)?.removePersistentDomain(forName: suite) }
        return KeyPolicyStore(defaults: UserDefaults(suiteName: suite)!)
    }

    private func policyModel(
        fingerprints: [String],
        overridden: [String] = [],
        hangs: Bool = false,
        failingForget: Bool = false
    ) -> PerKeyPolicyModel {
        let store = makeStore()
        for fingerprint in overridden {
            store.setPolicy(
                KeyPolicy(
                    biometry: .biometryCurrentSet,
                    accessibility: .whenPasscodeSet,
                    cacheTTLSeconds: 3600
                ),
                for: fingerprint
            )
        }
        let forget: PerKeyPolicyView.ForgetCallback = { _ in
            if failingForget { throw KeychainStoreError.userCanceled }
        }
        return PerKeyPolicyModel(
            store: store,
            enumerate: {
                if hangs { try? await Task.sleep(for: .seconds(60)) }
                return fingerprints
            },
            forget: forget
        )
    }

    private func sshManager(
        _ scAuth: StubSCAuth = StubSCAuth(identities: Fixtures.identities),
        agentKeys: [SSHAgentKey] = Fixtures.agentKeys
    ) -> SSHIdentityManager {
        SSHIdentityManager(scAuth: scAuth, sshAdd: StubSSHAdd(keys: agentKeys))
    }

    /// Hosts `view` in an unshown window, lets `.task` work finish, and snapshots it.
    private func snapshot<V: View>(
        _ view: V,
        dark: Bool,
        settle: Duration = .milliseconds(300),
        height: CGFloat = SettingsLayout.idealHeight
    ) async throws -> NSBitmapImageRep {
        let size = NSSize(width: SettingsLayout.idealWidth, height: height)
        let host = NSHostingView(rootView: view.frame(width: size.width, height: size.height))
        let window = NSWindow(
            contentRect: NSRect(origin: .zero, size: size),
            styleMask: [.titled],
            backing: .buffered,
            defer: false
        )
        window.isReleasedWhenClosed = false
        window.appearance = NSAppearance(named: dark ? .darkAqua : .aqua)
        window.contentView = host
        host.layoutSubtreeIfNeeded()
        try await Task.sleep(for: settle)
        host.layoutSubtreeIfNeeded()
        let rep = try XCTUnwrap(host.bitmapImageRepForCachingDisplay(in: host.bounds))
        host.cacheDisplay(in: host.bounds, to: rep)
        window.contentView = nil
        return rep
    }

    private func save(_ rep: NSBitmapImageRep, as name: String) throws {
        guard let outputDir else { return }
        try FileManager.default.createDirectory(at: outputDir, withIntermediateDirectories: true)
        let png = try XCTUnwrap(rep.representation(using: .png, properties: [:]))
        try png.write(to: outputDir.appending(path: "\(name).png"))
    }

    /// Brightness statistics over the visible (non-transparent) pixels.
    private func pixelStats(_ rep: NSBitmapImageRep) -> (distinct: Int, mean: Double) {
        var seen = Set<Int>()
        var total = 0.0
        var count = 0
        for x in stride(from: 0, to: rep.pixelsWide, by: 3) {
            for y in stride(from: 0, to: rep.pixelsHigh, by: 3) {
                guard let color = rep.colorAt(x: x, y: y)?.usingColorSpace(.deviceRGB),
                      color.alphaComponent > 0.5 else { continue }
                seen.insert(Int(color.brightnessComponent * 255))
                total += Double(color.brightnessComponent)
                count += 1
            }
        }
        return (seen.count, count == 0 ? 0 : total / Double(count))
    }

    private func renderBoth<V: View>(
        _ name: String,
        settle: Duration = .milliseconds(300),
        height: CGFloat = SettingsLayout.idealHeight,
        _ view: @autoclosure () -> V
    ) async throws {
        var means: [Double] = []
        for dark in [false, true] {
            let rep = try await snapshot(view(), dark: dark, settle: settle, height: height)
            let stats = pixelStats(rep)
            XCTAssertGreaterThan(stats.distinct, 8, "\(name) rendered blank")
            try save(rep, as: "\(name)-\(dark ? "dark" : "light")")
            means.append(stats.mean)
        }
        XCTAssertGreaterThan(
            abs(means[0] - means[1]), 0.05, "\(name): Light and Dark look identical"
        )
    }

    func testRootTabsRender() async throws {
        try await renderBoth("root", SettingsRootView())
    }

    func testKeychainTab() async throws {
        try await renderBoth(
            "keychain",
            KeychainSettingsView(keychainPrefs: .constant(UserPrefs()), clearAll: {})
        )
        try await renderBoth(
            "keychain-without-forget-all",
            KeychainSettingsView(keychainPrefs: .constant(UserPrefs()))
        )
    }

    func testPerKeyTab() async throws {
        let all = Fixtures.fingerprints
        try await renderBoth(
            "perkey-loaded",
            PerKeyPolicyView(model: self.policyModel(fingerprints: all, overridden: [all[1]]))
        )
        try await renderBoth(
            "perkey-empty",
            PerKeyPolicyView(model: self.policyModel(fingerprints: []))
        )
        try await renderBoth(
            "perkey-loading",
            PerKeyPolicyView(model: self.policyModel(fingerprints: all, hangs: true))
        )
    }

    func testPerKeyErrorBanner() async throws {
        let model = self.policyModel(fingerprints: Fixtures.fingerprints, failingForget: true)
        await model.load()
        await model.forget(Fixtures.fingerprints[0])
        XCTAssertNotNil(model.errorMessage)
        try await renderBoth("perkey-error", PerKeyPolicyView(model: model))
    }

    func testSSHTab() async throws {
        try await renderBoth("ssh-loaded", SSHIdentitiesView(manager: self.sshManager()))
        try await renderBoth(
            "ssh-empty",
            SSHIdentitiesView(manager: self.sshManager(StubSCAuth(), agentKeys: []))
        )
        try await renderBoth(
            "ssh-loading",
            SSHIdentitiesView(manager: self.sshManager(StubSCAuth(hangs: true)))
        )
        try await renderBoth(
            "ssh-error",
            SSHIdentitiesView(
                manager: self.sshManager(
                    StubSCAuth(failure: .commandFailed(exitCode: 1, stderr: "Touch ID cancelled"))
                )
            )
        )
        try await renderBoth(
            "ssh-warning",
            SSHIdentitiesView(
                manager: self.sshManager(
                    StubSCAuth(
                        identities: Fixtures.identities,
                        partial: .fingerprintCountMismatch(hexRows: 3, sshRows: 2)
                    )
                )
            )
        )
    }

    func testTallLayouts() async throws {
        let all = Fixtures.fingerprints
        try await renderBoth(
            "perkey-expanded",
            height: 760,
            PerKeyPolicyView(
                model: self.policyModel(fingerprints: all, overridden: [all[1]]),
                expanded: [all[1], all[0]]
            )
        )
        try await renderBoth(
            "ssh-tall",
            height: 1000,
            SSHIdentitiesView(manager: self.sshManager())
        )
    }

    func testWindowChrome() async throws {
        for tab in [SettingsTab.appearance, .perKey] {
            for dark in [false, true] {
                let host = NSHostingController(
                    rootView: SettingsRootView(
                        uiSettings: UISettings(),
                        keychainPrefs: UserPrefs(),
                        clearAllPassphrases: nil,
                        forgetPassphrase: nil,
                        saveUI: nil,
                        selection: tab
                    )
                )
                let window = NSWindow(contentViewController: host)
                window.styleMask = [.titled, .closable, .miniaturizable, .resizable]
                window.setContentSize(NSSize(width: 560, height: 400))
                window.appearance = NSAppearance(named: dark ? .darkAqua : .aqua)
                window.layoutIfNeeded()
                try await Task.sleep(for: .milliseconds(300))
                window.layoutIfNeeded()
                let labels = window.toolbar?.items.map(\.label)
                XCTAssertEqual(labels, SettingsTab.allCases.map(\.title))
                XCTAssertEqual(window.title, tab.title)
                let frameView = try XCTUnwrap(unsafe window.contentView?.superview)
                let bounds = frameView.bounds
                let rep = try XCTUnwrap(frameView.bitmapImageRepForCachingDisplay(in: bounds))
                frameView.cacheDisplay(in: frameView.bounds, to: rep)
                try save(rep, as: "chrome-\(tab.rawValue)-\(dark ? "dark" : "light")")
            }
        }
    }

    func testAboutTab() async throws {
        try await renderBoth("about", AboutView())
    }
}

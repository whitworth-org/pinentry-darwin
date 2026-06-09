// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// SCAuthClientGatedTests — touches the real macOS Secure Enclave via
// `/usr/sbin/sc_auth`. Will surface a Touch ID prompt. Gated behind
// PINENTRY_DARWIN_RUN_SC_AUTH_TESTS=1 so the default `swift test`
// run stays hermetic.
//
// Run with:  PINENTRY_DARWIN_RUN_SC_AUTH_TESTS=1 swift test \
//              --filter SSHIdentityTests.SCAuthClientGatedTests

import XCTest
@testable import SSHIdentity

final class SCAuthClientGatedTests: XCTestCase {

    private static var enabled: Bool {
        ProcessInfo.processInfo.environment["PINENTRY_DARWIN_RUN_SC_AUTH_TESTS"] == "1"
    }

    private func skipIfDisabled() throws {
        if !Self.enabled {
            throw XCTSkip("set PINENTRY_DARWIN_RUN_SC_AUTH_TESTS=1 to run")
        }
    }

    /// Use a per-run label so a leftover identity from a prior failed
    /// run does not collide. The cleanup `deleteIdentity` call in the
    /// test runs unconditionally; we still match by label as a
    /// belt-and-braces safety net.
    private func uniqueLabel() -> String {
        "pinentry-darwin-test-\(Int(Date().timeIntervalSince1970))"
    }

    // MARK: - End-to-end

    func testCreateListDelete() async throws {
        try skipIfDisabled()
        let client = SCAuthClient()
        let label = uniqueLabel()

        try await client.createIdentity(label: label)

        let identities = try await client.listIdentities().identities
        guard let row = identities.first(where: { $0.label == label }) else {
            // Clean up any matching label before failing so a partial
            // run doesn't leave a dangling SE identity.
            for candidate in identities where candidate.label.hasPrefix("pinentry-darwin-test-") {
                try? await client.deleteIdentity(publicKeyHash: candidate.publicKeyHash)
            }
            XCTFail("created identity '\(label)' not visible to list-ctk-identities")
            return
        }
        XCTAssertEqual(row.protection, .bio)
        XCTAssertEqual(row.keyType, .p256NE)
        XCTAssertNotNil(row.sshFingerprint)
        XCTAssertTrue(row.sshFingerprint?.hasPrefix("SHA256:") ?? false)

        try await client.deleteIdentity(publicKeyHash: row.publicKeyHash)

        let after = try await client.listIdentities().identities
        XCTAssertFalse(after.contains { $0.publicKeyHash == row.publicKeyHash })
    }
}

// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// SSHIdentityManagerTests — exercises the @MainActor manager via
// fake SCAuth/SSHAdd protocols. Verifies that successful operations
// update the published lists, that failures surface as `lastError`,
// and that `create` / `delete` trigger a follow-up refresh.

import XCTest
@testable import SSHIdentity

// MARK: - Test doubles

actor FakeSCAuth: SCAuthClientProtocol {
    var identities: [CTKIdentity] = []
    var partial: CTKIdentityListing.PartialReason?
    var nextError: SCAuthError?
    var createCalls: [String] = []
    var deleteCalls: [String] = []

    init(
        identities: [CTKIdentity] = [],
        partial: CTKIdentityListing.PartialReason? = nil
    ) {
        self.identities = identities
        self.partial = partial
    }

    func setError(_ error: SCAuthError?) { nextError = error }
    func setIdentities(_ rows: [CTKIdentity]) { identities = rows }
    func setPartial(_ reason: CTKIdentityListing.PartialReason?) { partial = reason }

    func listIdentities() async throws -> CTKIdentityListing {
        if let err = nextError { nextError = nil; throw err }
        return CTKIdentityListing(identities: identities, partial: partial)
    }

    func createIdentity(label: String) async throws {
        if let err = nextError { nextError = nil; throw err }
        createCalls.append(label)
        identities.append(CTKIdentity(
            keyType: .p256NE,
            publicKeyHash: String(repeating: "A", count: 40),
            sshFingerprint: "SHA256:fake",
            protection: .bio,
            label: label,
            commonName: label,
            emailAddress: "",
            validToRaw: "tomorrow",
            isValid: true
        ))
    }

    func deleteIdentity(publicKeyHash: String) async throws {
        if let err = nextError { nextError = nil; throw err }
        deleteCalls.append(publicKeyHash)
        identities.removeAll { $0.publicKeyHash == publicKeyHash }
    }
}

actor FakeSSHAdd: SSHAddClientProtocol {
    var agentKeys: [SSHAgentKey] = []
    var registeredFingerprints: [String] = []
    var nextError: SSHAddError?

    init(agentKeys: [SSHAgentKey] = []) {
        self.agentKeys = agentKeys
    }

    func setError(_ error: SSHAddError?) { nextError = error }

    func registerSecurityKeyProvider() async throws {
        if let err = nextError { nextError = nil; throw err }
        agentKeys.append(SSHAgentKey(
            keyType: "sk-ecdsa-sha2-nistp256@openssh.com",
            base64Blob: "AAAA",
            comment: "ssh:registered",
            rawLine: "sk-ecdsa-sha2-nistp256@openssh.com AAAA ssh:registered"
        ))
        registeredFingerprints.append("SHA256:fake")
    }

    func listAgentIdentities() async throws -> [SSHAgentKey] {
        if let err = nextError { nextError = nil; throw err }
        return agentKeys
    }
}

// MARK: - Tests

@MainActor
final class SSHIdentityManagerTests: XCTestCase {

    func testRefreshPopulatesIdentitiesAndAgentKeys() async {
        let initial = CTKIdentity(
            keyType: .p256NE,
            publicKeyHash: String(repeating: "B", count: 40),
            sshFingerprint: nil,
            protection: .bio,
            label: "ssh-laptop",
            commonName: "ssh-laptop",
            emailAddress: "",
            validToRaw: "soon",
            isValid: true
        )
        let agent = SSHAgentKey(
            keyType: "sk-ecdsa-sha2-nistp256@openssh.com",
            base64Blob: "AAAA",
            comment: "ssh:laptop",
            rawLine: "sk-ecdsa-sha2-nistp256@openssh.com AAAA ssh:laptop"
        )
        let scAuth = FakeSCAuth(identities: [initial])
        let sshAdd = FakeSSHAdd(agentKeys: [agent])
        let manager = SSHIdentityManager(scAuth: scAuth, sshAdd: sshAdd)

        await manager.refresh()
        XCTAssertEqual(manager.identities.count, 1)
        XCTAssertEqual(manager.agentKeys.count, 1)
        XCTAssertNil(manager.lastError)
        XCTAssertNil(manager.lastWarning)
        XCTAssertFalse(manager.isBusy)
    }

    // L-10: a partial (truncated) sc_auth listing surfaces a non-fatal
    // warning while still populating the usable list — not a thrown
    // error, and not silent truncation.
    func testRefreshSurfacesPartialListingAsWarning() async {
        let row = CTKIdentity(
            keyType: .p256NE,
            publicKeyHash: String(repeating: "D", count: 40),
            sshFingerprint: nil,
            protection: .bio,
            label: "ssh-x",
            commonName: "ssh-x",
            emailAddress: "",
            validToRaw: "",
            isValid: true
        )
        let scAuth = FakeSCAuth(
            identities: [row],
            partial: .fingerprintCountMismatch(hexRows: 1, sshRows: 0)
        )
        let manager = SSHIdentityManager(scAuth: scAuth, sshAdd: FakeSSHAdd())

        await manager.refresh()
        XCTAssertEqual(manager.identities.count, 1)
        XCTAssertNil(manager.lastError)
        XCTAssertNotNil(manager.lastWarning)
        XCTAssertTrue(manager.lastWarning?.contains("could not be paired") ?? false)

        manager.dismissWarning()
        XCTAssertNil(manager.lastWarning)
    }

    // A subsequent clean refresh clears a stale partial warning.
    func testCleanRefreshClearsStaleWarning() async {
        let scAuth = FakeSCAuth(
            identities: [],
            partial: .fingerprintCountMismatch(hexRows: 1, sshRows: 0)
        )
        let manager = SSHIdentityManager(scAuth: scAuth, sshAdd: FakeSSHAdd())
        await manager.refresh()
        XCTAssertNotNil(manager.lastWarning)

        await scAuth.setPartial(nil)
        await manager.refresh()
        XCTAssertNil(manager.lastWarning)
    }

    func testRefreshSurfacesErrorAsLastError() async {
        let scAuth = FakeSCAuth()
        await scAuth.setError(.commandFailed(exitCode: 7, stderr: "nope"))
        let manager = SSHIdentityManager(scAuth: scAuth, sshAdd: FakeSSHAdd())

        await manager.refresh()
        XCTAssertNotNil(manager.lastError)
        XCTAssertTrue(manager.lastError?.contains("sc_auth exit 7") ?? false)
        XCTAssertFalse(manager.isBusy)
    }

    func testCreateAppendsAndRefreshes() async {
        let scAuth = FakeSCAuth()
        let manager = SSHIdentityManager(scAuth: scAuth, sshAdd: FakeSSHAdd())

        await manager.create(label: "ssh-test")
        XCTAssertEqual(manager.identities.count, 1)
        XCTAssertEqual(manager.identities[0].label, "ssh-test")
        let createCalls = await scAuth.createCalls
        XCTAssertEqual(createCalls, ["ssh-test"])
    }

    func testDeleteRemovesAndRefreshes() async {
        let row = CTKIdentity(
            keyType: .p256NE,
            publicKeyHash: String(repeating: "C", count: 40),
            sshFingerprint: nil,
            protection: .bio,
            label: "ssh-a",
            commonName: "ssh-a",
            emailAddress: "",
            validToRaw: "",
            isValid: true
        )
        let scAuth = FakeSCAuth(identities: [row])
        let manager = SSHIdentityManager(scAuth: scAuth, sshAdd: FakeSSHAdd())
        await manager.refresh()
        XCTAssertEqual(manager.identities.count, 1)

        await manager.delete(row)
        XCTAssertEqual(manager.identities.count, 0)
        let deleteCalls = await scAuth.deleteCalls
        XCTAssertEqual(deleteCalls, [String(repeating: "C", count: 40)])
    }

    func testRegisterWithAgentUpdatesAgentKeys() async {
        let scAuth = FakeSCAuth()
        let sshAdd = FakeSSHAdd()
        let manager = SSHIdentityManager(scAuth: scAuth, sshAdd: sshAdd)

        await manager.registerWithAgent()
        XCTAssertEqual(manager.agentKeys.count, 1)
        XCTAssertTrue(manager.agentKeys[0].isSecurityKey)
        XCTAssertNil(manager.lastError)
    }

    func testDismissErrorClearsState() async {
        let scAuth = FakeSCAuth()
        await scAuth.setError(.commandFailed(exitCode: 1, stderr: "x"))
        let manager = SSHIdentityManager(scAuth: scAuth, sshAdd: FakeSSHAdd())
        await manager.refresh()
        XCTAssertNotNil(manager.lastError)
        manager.dismissError()
        XCTAssertNil(manager.lastError)
    }

    func testInvalidLabelSurfacesActionableMessage() async {
        let scAuth = FakeSCAuth()
        await scAuth.setError(.invalidLabel("bad label"))
        let manager = SSHIdentityManager(scAuth: scAuth, sshAdd: FakeSSHAdd())
        await manager.refresh()
        XCTAssertTrue(manager.lastError?.contains("Invalid label") ?? false)
    }
}

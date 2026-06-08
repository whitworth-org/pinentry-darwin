// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// SCAuthClientTests — hermetic tests for the SCAuthClient actor
// using `MockProcessRunner`. Verifies that the argv passed to
// sc_auth matches the design (no shell, pinned binary), that
// list-merge logic correctly pairs the hex-hash and ssh-fingerprint
// outputs, and that label / hash validation rejects shell-unsafe
// values BEFORE any subprocess fires.

import XCTest
@testable import SSHIdentity

final class SCAuthClientTests: XCTestCase {

    private let headerHex =
        "Key Type Public Key Hash                          Prot Label Common Name Email Address Valid To        Valid"
    private let headerSSH =
        "Key Type Public Key Hash                                    Prot Label Common Name Email Address Valid To        Valid"

    // MARK: - listIdentities — merge path

    func testListMergesHexAndSSHFingerprints() async throws {
        let hexOut = headerHex + "\n" +
            "p-256-ne A71277F0BC5825A7B3576D014F31282A866EF3BC bio  ssh   ssh                       23.11.26, 17:09 YES\n"
        let sshOut = headerSSH + "\n" +
            "p-256-ne SHA256:vs4ByYo+T9M3V8iiDYONMSvx2k5Fj2ujVBWt1j6yzis bio  ssh   ssh                       23.11.26, 17:09 YES\n"

        let mock = MockProcessRunner(byArgs: [
            ["list-ctk-identities"]:
                ProcessResult(exitCode: 0, stdout: hexOut, stderr: ""),
            ["list-ctk-identities", "-t", "ssh"]:
                ProcessResult(exitCode: 0, stdout: sshOut, stderr: ""),
        ])

        let client = SCAuthClient(binary: "/usr/sbin/sc_auth", runner: mock)
        let listing = try await client.listIdentities()
        XCTAssertNil(listing.partial)
        let identities = listing.identities
        XCTAssertEqual(identities.count, 1)
        XCTAssertEqual(identities[0].publicKeyHash, "A71277F0BC5825A7B3576D014F31282A866EF3BC")
        XCTAssertEqual(identities[0].sshFingerprint, "SHA256:vs4ByYo+T9M3V8iiDYONMSvx2k5Fj2ujVBWt1j6yzis")
        XCTAssertEqual(identities[0].label, "ssh")

        let calls = await mock.calls
        XCTAssertEqual(calls.count, 2)
        XCTAssertEqual(calls[0].executable, "/usr/sbin/sc_auth")
        XCTAssertEqual(calls[0].arguments, ["list-ctk-identities"])
        XCTAssertEqual(calls[1].arguments, ["list-ctk-identities", "-t", "ssh"])
    }

    // L-10: a hex/ssh row-count mismatch must not silently truncate.
    // We still return best-effort hex rows, but flag the partial result
    // so the manager can surface it to the operator.
    func testListFlagsPartialWhenSSHCountMismatches() async throws {
        let hexOut = headerHex + "\n" +
            "p-256-ne A71277F0BC5825A7B3576D014F31282A866EF3BC bio  ssh-a ssh-a                     23.11.26, 17:09 YES\n" +
            "p-256-ne B71277F0BC5825A7B3576D014F31282A866EF3BC bio  ssh-b ssh-b                     23.11.26, 17:09 YES\n"
        let sshOut = headerSSH + "\n"  // header only, zero rows

        let mock = MockProcessRunner(byArgs: [
            ["list-ctk-identities"]:
                ProcessResult(exitCode: 0, stdout: hexOut, stderr: ""),
            ["list-ctk-identities", "-t", "ssh"]:
                ProcessResult(exitCode: 0, stdout: sshOut, stderr: ""),
        ])

        let client = SCAuthClient(binary: "/usr/sbin/sc_auth", runner: mock)
        let listing = try await client.listIdentities()
        XCTAssertEqual(listing.identities.count, 2)
        XCTAssertNil(listing.identities[0].sshFingerprint)
        XCTAssertEqual(
            listing.partial,
            .fingerprintCountMismatch(hexRows: 2, sshRows: 0)
        )
    }

    func testListSurfacesParseErrorOnBadHeader() async {
        let mock = MockProcessRunner(byArgs: [
            ["list-ctk-identities"]:
                ProcessResult(exitCode: 0, stdout: "Some Other Header\n", stderr: ""),
            ["list-ctk-identities", "-t", "ssh"]:
                ProcessResult(exitCode: 0, stdout: "", stderr: ""),
        ])

        let client = SCAuthClient(binary: "/usr/sbin/sc_auth", runner: mock)
        do {
            _ = try await client.listIdentities()
            XCTFail("expected parse error")
        } catch let SCAuthError.parseError(inner) {
            switch inner {
            case .unrecognisedHeader:
                break
            default:
                XCTFail("expected unrecognisedHeader, got \(inner)")
            }
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testListSurfacesNonZeroExit() async {
        let mock = MockProcessRunner(byArgs: [
            ["list-ctk-identities"]:
                ProcessResult(exitCode: 2, stdout: "", stderr: "boom"),
        ])
        let client = SCAuthClient(binary: "/usr/sbin/sc_auth", runner: mock)
        do {
            _ = try await client.listIdentities()
            XCTFail("expected commandFailed")
        } catch let SCAuthError.commandFailed(code, stderr) {
            XCTAssertEqual(code, 2)
            XCTAssertEqual(stderr, "boom")
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    // MARK: - createIdentity

    func testCreateIdentityPassesExpectedArgv() async throws {
        let mock = MockProcessRunner(fallback: [
            ProcessResult(exitCode: 0, stdout: "", stderr: ""),
        ])
        let client = SCAuthClient(binary: "/usr/sbin/sc_auth", runner: mock)
        try await client.createIdentity(label: "ssh-laptop")

        let calls = await mock.calls
        XCTAssertEqual(calls.count, 1)
        XCTAssertEqual(calls[0].arguments, [
            "create-ctk-identity", "-l", "ssh-laptop", "-k", "p-256-ne", "-t", "bio",
        ])
    }

    func testCreateIdentityRejectsShellMetacharacters() async {
        let client = SCAuthClient(binary: "/usr/sbin/sc_auth", runner: MockProcessRunner())
        for bad in ["ssh; rm -rf /", "ssh`whoami`", "ssh$(id)", "ssh\nrm", "ssh /etc/passwd"] {
            do {
                try await client.createIdentity(label: bad)
                XCTFail("expected invalidLabel for '\(bad)'")
            } catch SCAuthError.invalidLabel {
                // expected
            } catch {
                XCTFail("unexpected error for '\(bad)': \(error)")
            }
        }
    }

    // MARK: - deleteIdentity

    func testDeleteIdentityPassesExpectedArgv() async throws {
        let mock = MockProcessRunner(fallback: [
            ProcessResult(exitCode: 0, stdout: "", stderr: ""),
        ])
        let client = SCAuthClient(binary: "/usr/sbin/sc_auth", runner: mock)
        try await client.deleteIdentity(publicKeyHash: "A71277F0BC5825A7B3576D014F31282A866EF3BC")

        let calls = await mock.calls
        XCTAssertEqual(calls[0].arguments, [
            "delete-ctk-identity", "-h", "A71277F0BC5825A7B3576D014F31282A866EF3BC",
        ])
    }

    func testDeleteIdentityRejectsNonHexHash() async {
        let client = SCAuthClient(binary: "/usr/sbin/sc_auth", runner: MockProcessRunner())
        do {
            try await client.deleteIdentity(publicKeyHash: "not-a-hash")
            XCTFail("expected invalidHash")
        } catch SCAuthError.invalidHash {
            // expected
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }
}

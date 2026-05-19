// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// SSHAddClientTests — hermetic tests for SSHAddClient.
// Verifies that the argv passed to ssh-add matches the design
// (pinned provider path, no shell), that "agent has no identities"
// is handled as success-with-empty-list, and that exit-1 with that
// message is not treated as a failure.

import XCTest
@testable import SSHIdentity

final class SSHAddClientTests: XCTestCase {

    // MARK: - registerSecurityKeyProvider

    func testRegisterPassesExpectedArgv() async throws {
        let mock = MockProcessRunner(fallback: [
            ProcessResult(
                exitCode: 0,
                stdout: "Resident identity added: ECDSA-SK SHA256:abc\n",
                stderr: ""
            ),
        ])
        let client = SSHAddClient(
            binary: "/usr/bin/ssh-add",
            provider: "/usr/lib/ssh-keychain.dylib",
            runner: mock
        )
        let fps = try await client.registerSecurityKeyProvider()
        XCTAssertEqual(fps, ["SHA256:abc"])

        let calls = await mock.calls
        XCTAssertEqual(calls[0].executable, "/usr/bin/ssh-add")
        XCTAssertEqual(calls[0].arguments, ["-K", "-S", "/usr/lib/ssh-keychain.dylib"])
    }

    func testRegisterSurfacesNonZeroExit() async {
        let mock = MockProcessRunner(fallback: [
            ProcessResult(exitCode: 1, stdout: "", stderr: "bad provider"),
        ])
        let client = SSHAddClient(runner: mock)
        do {
            _ = try await client.registerSecurityKeyProvider()
            XCTFail("expected commandFailed")
        } catch let SSHAddError.commandFailed(code, stderr) {
            XCTAssertEqual(code, 1)
            XCTAssertEqual(stderr, "bad provider")
        } catch {
            XCTFail("unexpected: \(error)")
        }
    }

    // MARK: - listAgentIdentities

    func testListAgentReturnsParsedKeys() async throws {
        let stdout = "sk-ecdsa-sha2-nistp256@openssh.com AAAA ssh:test\n"
        let mock = MockProcessRunner(fallback: [
            ProcessResult(exitCode: 0, stdout: stdout, stderr: ""),
        ])
        let client = SSHAddClient(runner: mock)
        let keys = try await client.listAgentIdentities()
        XCTAssertEqual(keys.count, 1)
        XCTAssertEqual(keys[0].keyType, "sk-ecdsa-sha2-nistp256@openssh.com")
        XCTAssertTrue(keys[0].isSecurityKey)
    }

    func testListAgentTreatsNoIdentitiesAsEmpty() async throws {
        // ssh-add -L exits 1 with this message when the agent is empty;
        // we must treat that as "empty list", not as an error.
        let mock = MockProcessRunner(fallback: [
            ProcessResult(exitCode: 1, stdout: "The agent has no identities.\n", stderr: ""),
        ])
        let client = SSHAddClient(runner: mock)
        let keys = try await client.listAgentIdentities()
        XCTAssertEqual(keys, [])
    }

    func testListAgentSurfacesUnexpectedFailure() async {
        let mock = MockProcessRunner(fallback: [
            ProcessResult(exitCode: 2, stdout: "", stderr: "could not open connection"),
        ])
        let client = SSHAddClient(runner: mock)
        do {
            _ = try await client.listAgentIdentities()
            XCTFail("expected commandFailed")
        } catch let SSHAddError.commandFailed(code, _) {
            XCTAssertEqual(code, 2)
        } catch {
            XCTFail("unexpected: \(error)")
        }
    }
}

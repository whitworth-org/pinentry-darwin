// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// OutputParsersTests — fully hermetic. Feeds canned `sc_auth` and
// `ssh-add` output to the parser functions and asserts on the
// resulting Swift value types.

import XCTest
@testable import SSHIdentity

final class OutputParsersTests: XCTestCase {

    // MARK: - sc_auth list-ctk-identities (hex hash variant)

    private let headerHex =
        "Key Type Public Key Hash                          Prot Label Common Name Email Address Valid To        Valid"

    private let headerSSH =
        "Key Type Public Key Hash                                    Prot Label Common Name Email Address Valid To        Valid"

    func testEmptyListHexParsesAsZeroRows() throws {
        let rows = try parseSCAuthList(
            headerHex + "\n",
            interpretingHashAsSSHFingerprint: false
        )
        XCTAssertEqual(rows.count, 0)
    }

    func testSingleSSHIdentityHexHash() throws {
        let output = headerHex + "\n" +
            "p-256-ne A71277F0BC5825A7B3576D014F31282A866EF3BC bio  ssh   ssh                       23.11.26, 17:09 YES"
        let rows = try parseSCAuthList(output, interpretingHashAsSSHFingerprint: false)
        XCTAssertEqual(rows.count, 1)
        let row = rows[0]
        XCTAssertEqual(row.keyType, .p256NE)
        XCTAssertEqual(row.publicKeyHash, "A71277F0BC5825A7B3576D014F31282A866EF3BC")
        XCTAssertEqual(row.protection, .bio)
        XCTAssertEqual(row.label, "ssh")
        XCTAssertEqual(row.commonName, "ssh")
        XCTAssertEqual(row.emailAddress, "")
        XCTAssertEqual(row.validToRaw, "23.11.26, 17:09")
        XCTAssertTrue(row.isValid)
        XCTAssertNil(row.sshFingerprint)
        XCTAssertTrue(row.isSSHLabelled)
    }

    func testSingleSSHIdentitySSHFingerprintVariant() throws {
        let output = headerSSH + "\n" +
            "p-256-ne SHA256:vs4ByYo+T9M3V8iiDYONMSvx2k5Fj2ujVBWt1j6yzis bio  ssh   ssh                       23.11.26, 17:09 YES"
        let rows = try parseSCAuthList(output, interpretingHashAsSSHFingerprint: true)
        XCTAssertEqual(rows.count, 1)
        let row = rows[0]
        XCTAssertEqual(row.sshFingerprint, "SHA256:vs4ByYo+T9M3V8iiDYONMSvx2k5Fj2ujVBWt1j6yzis")
        XCTAssertEqual(row.publicKeyHash, "SHA256:vs4ByYo+T9M3V8iiDYONMSvx2k5Fj2ujVBWt1j6yzis")
        XCTAssertEqual(row.label, "ssh")
    }

    func testInvalidIdentityRowReportsNo() throws {
        // Label width matches the standard header ("Label" — 5 chars
        // wide) so the row aligns. sc_auth auto-pads the header to the
        // widest data row at runtime; this fixture sticks to the
        // narrow form for simplicity.
        let output = headerHex + "\n" +
            "p-256    A581E5404ED157C4C73FFDBDFC1339E0D873FCAE bio  ssh   ssh                       23.11.26, 19:50 NO"
        let rows = try parseSCAuthList(output, interpretingHashAsSSHFingerprint: false)
        XCTAssertEqual(rows.count, 1)
        XCTAssertEqual(rows[0].keyType, .p256)
        XCTAssertEqual(rows[0].label, "ssh")
        XCTAssertFalse(rows[0].isValid)
    }

    func testWidenedLabelColumnParses() throws {
        // sc_auth widens the header AND each row when a label is
        // long enough to require it. The parser must follow the
        // header's column widths — so a longer "Label" header means a
        // proportionally wider column.
        let widerHeader =
            "Key Type Public Key Hash                          Prot Label          Common Name    Email Address Valid To        Valid"
        let row =
            "p-256-ne A71277F0BC5825A7B3576D014F31282A866EF3BC bio  ssh-exportable ssh-exportable               23.11.26, 19:50 YES"
        let rows = try parseSCAuthList(widerHeader + "\n" + row, interpretingHashAsSSHFingerprint: false)
        XCTAssertEqual(rows.count, 1)
        XCTAssertEqual(rows[0].label, "ssh-exportable")
        XCTAssertEqual(rows[0].commonName, "ssh-exportable")
    }

    func testMultipleRows() throws {
        let output = headerHex + "\n" +
            "p-256-ne A71277F0BC5825A7B3576D014F31282A866EF3BC bio  ssh-a ssh-a                     23.11.26, 17:09 YES\n" +
            "p-256    A581E5404ED157C4C73FFDBDFC1339E0D873FCAE bio  ssh-b ssh-b                     23.11.26, 19:50 YES\n"
        let rows = try parseSCAuthList(output, interpretingHashAsSSHFingerprint: false)
        XCTAssertEqual(rows.count, 2)
        XCTAssertEqual(rows[0].label, "ssh-a")
        XCTAssertEqual(rows[1].label, "ssh-b")
    }

    func testEmptyOutputThrows() {
        XCTAssertThrowsError(try parseSCAuthList("", interpretingHashAsSSHFingerprint: false)) { err in
            XCTAssertEqual(err as? SSHIdentityParseError, .emptyOutput)
        }
    }

    func testUnrecognisedHeaderThrows() {
        let badHeader = "Some Other Header Line"
        XCTAssertThrowsError(try parseSCAuthList(badHeader, interpretingHashAsSSHFingerprint: false)) { err in
            switch err {
            case SSHIdentityParseError.unrecognisedHeader:
                break
            default:
                XCTFail("expected unrecognisedHeader, got \(err)")
            }
        }
    }

    // MARK: - Column locator

    func testColumnLocatorDistinguishesValidAndValidTo() throws {
        let columns = try locateColumns(in: headerHex)
        XCTAssertEqual(columns.map(\.name), [
            "Key Type",
            "Public Key Hash",
            "Prot",
            "Label",
            "Common Name",
            "Email Address",
            "Valid To",
            "Valid",
        ])
        // The trailing "Valid" must start AFTER "Valid To"'s end.
        let validTo = columns.first { $0.name == "Valid To" }!
        let valid = columns.first { $0.name == "Valid" }!
        XCTAssertGreaterThan(valid.start, validTo.start)
    }

    // MARK: - ssh-add -L

    func testSSHAddListEmptyAgent() {
        let out = "The agent has no identities.\n"
        XCTAssertEqual(parseSSHAddList(out), [])
    }

    func testSSHAddListSingleKey() {
        let line = "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNh ssh:test"
        let keys = parseSSHAddList(line + "\n")
        XCTAssertEqual(keys.count, 1)
        XCTAssertEqual(keys[0].keyType, "sk-ecdsa-sha2-nistp256@openssh.com")
        XCTAssertEqual(keys[0].base64Blob, "AAAAInNrLWVjZHNh")
        XCTAssertEqual(keys[0].comment, "ssh:test")
        XCTAssertEqual(keys[0].rawLine, line)
        XCTAssertTrue(keys[0].isSecurityKey)
    }

    func testSSHAddListKeyWithoutComment() {
        let line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5"
        let keys = parseSSHAddList(line + "\n")
        XCTAssertEqual(keys.count, 1)
        XCTAssertEqual(keys[0].keyType, "ssh-ed25519")
        XCTAssertEqual(keys[0].comment, "")
        XCTAssertFalse(keys[0].isSecurityKey)
    }

    func testSSHAddListMultipleKeys() {
        let out = """
        sk-ecdsa-sha2-nistp256@openssh.com AAAA111 a@b
        ssh-ed25519 AAAA222 user@host
        """
        let keys = parseSSHAddList(out)
        XCTAssertEqual(keys.count, 2)
        XCTAssertEqual(keys[0].keyType, "sk-ecdsa-sha2-nistp256@openssh.com")
        XCTAssertEqual(keys[1].keyType, "ssh-ed25519")
    }

    // L-9: a key whose comment merely contains the empty-agent sentinel
    // must still parse. Only a whole-line match for the sentinel is the
    // empty-agent marker.
    func testSSHAddListKeepsKeyWithSentinelInComment() {
        let line = "ssh-ed25519 AAAA333 the agent has no identities"
        let keys = parseSSHAddList(line + "\n")
        XCTAssertEqual(keys.count, 1)
        XCTAssertEqual(keys[0].keyType, "ssh-ed25519")
        XCTAssertEqual(keys[0].comment, "the agent has no identities")
    }

    // MARK: - Validation

    func testLabelValidation() {
        XCTAssertTrue(validateLabel("ssh"))
        XCTAssertTrue(validateLabel("ssh-laptop"))
        XCTAssertTrue(validateLabel("ssh_2026.05"))
        XCTAssertTrue(validateLabel(String(repeating: "a", count: 64)))

        XCTAssertFalse(validateLabel(""))
        XCTAssertFalse(validateLabel("ssh with space"))
        XCTAssertFalse(validateLabel("ssh;rm -rf"))
        XCTAssertFalse(validateLabel("ssh$(whoami)"))
        XCTAssertFalse(validateLabel("ssh\nrm"))
        XCTAssertFalse(validateLabel(String(repeating: "a", count: 65)))
    }

    func testHashValidation() {
        XCTAssertTrue(validatePublicKeyHash("A71277F0BC5825A7B3576D014F31282A866EF3BC"))
        XCTAssertTrue(validatePublicKeyHash("a71277f0bc5825a7b3576d014f31282a866ef3bc"))

        XCTAssertFalse(validatePublicKeyHash(""))
        XCTAssertFalse(validatePublicKeyHash("A71277F0BC5825A7B3576D014F31282A866EF3B"))   // 39
        XCTAssertFalse(validatePublicKeyHash("A71277F0BC5825A7B3576D014F31282A866EF3BCD"))  // 41
        XCTAssertFalse(validatePublicKeyHash("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"))
        XCTAssertFalse(validatePublicKeyHash("SHA256:vs4ByYo+T9M3V8iiDYONMSvx2k5Fj2ujVBWt1j6yzis"))
    }
}

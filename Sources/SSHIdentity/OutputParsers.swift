// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// OutputParsers.swift — pure functions that turn the human-readable
// output of `sc_auth list-ctk-identities`, `ssh-add -K`, and
// `ssh-add -L` into Swift value types.
//
// Parsing strategy: the sc_auth output is column-aligned text rather
// than tab/CSV. The first line is a header that contains each
// well-known column name. We locate the start byte-offset of each
// known column name in the header and use those offsets to slice each
// data row. This survives variable-width columns (e.g. hex hash vs.
// `SHA256:<base64>` fingerprint) without depending on a fixed schema.
//
// Hermetic: no I/O, no Foundation Process, no global state.

import Foundation

// MARK: - sc_auth

/// Column names emitted by `sc_auth list-ctk-identities` (with and
/// without `-t ssh`). Order matches the CLI header. Each name appears
/// verbatim in the header line; we use that to locate column starts.
private let scAuthColumns: [String] = [
    "Key Type",
    "Public Key Hash",
    "Prot",
    "Label",
    "Common Name",
    "Email Address",
    "Valid To",
    "Valid",
]

/// Parse `sc_auth list-ctk-identities` output (with or without
/// `-t ssh`). Returns an empty array when the output contains only a
/// header line. The second parameter controls whether the public-key-
/// hash column is interpreted as an SSH fingerprint (`-t ssh`) or as
/// the hex SHA-1 hash used by `delete-ctk-identity -h`.
///
/// Throws when the header line is missing a known column or the input
/// is empty. We do not throw on per-row parse problems — a malformed
/// row is skipped and the rest of the output still parses, since the
/// CLI may add columns over time and we want forward compatibility.
public func parseSCAuthList(
    _ output: String,
    interpretingHashAsSSHFingerprint: Bool
) throws -> [CTKIdentity] {
    let lines = output
        .split(separator: "\n", omittingEmptySubsequences: false)
        .map(String.init)
    guard let header = lines.first, !header.trimmingCharacters(in: .whitespaces).isEmpty else {
        throw SSHIdentityParseError.emptyOutput
    }
    let columns = try locateColumns(in: header)

    var out: [CTKIdentity] = []
    for raw in lines.dropFirst() {
        let trimmed = raw.trimmingCharacters(in: .whitespaces)
        if trimmed.isEmpty { continue }
        guard let row = parseSCAuthRow(
            raw,
            columns: columns,
            interpretingHashAsSSHFingerprint: interpretingHashAsSSHFingerprint
        ) else { continue }
        out.append(row)
    }
    return out
}

/// A located column from the header line. `start` is the byte offset
/// where the column name begins; `end` is the byte offset where the
/// next column begins (or `Int.max` for the last column).
struct LocatedColumn: Equatable {
    let name: String
    let start: Int
    let end: Int
}

func locateColumns(in header: String) throws -> [LocatedColumn] {
    // Walk the known column names in left-to-right order and advance a
    // cursor past each match. This avoids the "Valid" / "Valid To"
    // substring collision and also catches the case where a column is
    // missing or out of order.
    var cursor = header.startIndex
    var hits: [(name: String, start: Int)] = []
    for name in scAuthColumns {
        guard let range = header.range(of: name, range: cursor..<header.endIndex) else {
            throw SSHIdentityParseError.unrecognisedHeader(header)
        }
        let offset = header.utf8.distance(
            from: header.utf8.startIndex,
            to: range.lowerBound.samePosition(in: header.utf8) ?? header.utf8.startIndex
        )
        hits.append((name, offset))
        cursor = range.upperBound
    }
    var out: [LocatedColumn] = []
    for (idx, hit) in hits.enumerated() {
        let end = (idx + 1 < hits.count) ? hits[idx + 1].start : Int.max
        out.append(LocatedColumn(name: hit.name, start: hit.start, end: end))
    }
    return out
}

private func parseSCAuthRow(
    _ raw: String,
    columns: [LocatedColumn],
    interpretingHashAsSSHFingerprint: Bool
) -> CTKIdentity? {
    var fields: [String: String] = [:]
    let bytes = Array(raw.utf8)
    for col in columns {
        guard col.start < bytes.count else {
            fields[col.name] = ""
            continue
        }
        let end = min(col.end, bytes.count)
        let slice = bytes[col.start..<end]
        let str = String(decoding: slice, as: UTF8.self)
            .trimmingCharacters(in: .whitespaces)
        fields[col.name] = str
    }

    guard let hashOrFingerprint = fields["Public Key Hash"],
          !hashOrFingerprint.isEmpty,
          let label = fields["Label"]
    else { return nil }

    let keyType = (fields["Key Type"]).flatMap { CTKKeyType(rawValue: $0) }
    let protection = CTKProtection(rawValue: fields["Prot"] ?? "")
        ?? .unknown

    let publicKeyHash: String
    let sshFingerprint: String?
    if interpretingHashAsSSHFingerprint {
        sshFingerprint = hashOrFingerprint
        publicKeyHash = hashOrFingerprint
    } else {
        publicKeyHash = hashOrFingerprint
        sshFingerprint = nil
    }

    return CTKIdentity(
        keyType: keyType,
        publicKeyHash: publicKeyHash,
        sshFingerprint: sshFingerprint,
        protection: protection,
        label: label,
        commonName: fields["Common Name"] ?? "",
        emailAddress: fields["Email Address"] ?? "",
        validToRaw: fields["Valid To"] ?? "",
        isValid: (fields["Valid"] ?? "").uppercased() == "YES"
    )
}

// MARK: - ssh-add -L

/// Parse `ssh-add -L` output into agent-resident key descriptions.
/// Returns an empty array when the agent reports no identities (which
/// `ssh-add -L` prints to stderr with exit 1, but the caller may pass
/// the stdout-only string here).
public func parseSSHAddList(_ output: String) -> [SSHAgentKey] {
    var out: [SSHAgentKey] = []
    for raw in output.split(separator: "\n", omittingEmptySubsequences: true) {
        let line = String(raw)
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        if trimmed.isEmpty { continue }
        // Skip the empty-agent sentinel only when the WHOLE line is the
        // message — not a substring, so a key whose comment contains the
        // phrase is still parsed.
        let sentinel = trimmed.lowercased()
            .trimmingCharacters(in: CharacterSet(charactersIn: "."))
        if sentinel == "the agent has no identities" {
            continue
        }
        let parts = trimmed.split(
            separator: " ",
            maxSplits: 2,
            omittingEmptySubsequences: true
        )
        guard parts.count >= 2 else { continue }
        let comment = parts.count >= 3 ? String(parts[2]) : ""
        out.append(SSHAgentKey(
            keyType: String(parts[0]),
            base64Blob: String(parts[1]),
            comment: comment,
            rawLine: trimmed
        ))
    }
    return out
}

// MARK: - Errors

public enum SSHIdentityParseError: Error, Equatable, Sendable {
    case emptyOutput
    case unrecognisedHeader(String)
}

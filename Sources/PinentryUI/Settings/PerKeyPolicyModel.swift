// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// PerKeyPolicyModel.swift — state and actions behind Settings → Per-key policy.
//
// Keychain enumeration and deletion run off the main actor; this model only
// holds the results. A per-key override is removed only after the Keychain
// delete succeeds, so a failed or cancelled delete never loses a policy.

import Foundation
import KeychainStore
import Observation

@MainActor
@Observable
final class PerKeyPolicyModel {

    typealias Enumerate = @concurrent @Sendable () async -> [String]

    enum Phase: Equatable {
        case loading
        case loaded
    }

    struct Row: Identifiable, Equatable {
        let fingerprint: String
        let policy: KeyPolicy
        let hasOverride: Bool
        var id: String { fingerprint }
    }

    private(set) var phase: Phase = .loading
    private(set) var rows: [Row] = []
    private(set) var defaultPolicy: KeyPolicy
    /// Fingerprint whose Keychain delete is in flight, if any.
    private(set) var forgetting: String?
    /// Concise description of the last failed action, shown until dismissed.
    var errorMessage: String?

    private let store: KeyPolicyStore
    private let enumerate: Enumerate
    private let forgetCallback: PerKeyPolicyView.ForgetCallback?

    init(
        store: KeyPolicyStore,
        enumerate: @escaping Enumerate,
        forget: PerKeyPolicyView.ForgetCallback?
    ) {
        self.store = store
        self.enumerate = enumerate
        self.forgetCallback = forget
        self.defaultPolicy = store.defaultPolicy
    }

    var canForget: Bool { forgetCallback != nil }

    func load() async {
        let found = await enumerate()
        defaultPolicy = store.defaultPolicy
        rows = found.sorted().map(makeRow)
        phase = .loaded
    }

    func setDefault(_ policy: KeyPolicy) {
        store.setDefaultPolicy(policy)
        defaultPolicy = policy
        rows = rows.map { makeRow($0.fingerprint) }
    }

    func setPolicy(_ policy: KeyPolicy, for fingerprint: String) {
        store.setPolicy(policy, for: fingerprint)
        replaceRow(fingerprint)
    }

    func resetOverride(for fingerprint: String) {
        store.removeOverride(for: fingerprint)
        replaceRow(fingerprint)
    }

    /// Delete the saved passphrase for `fingerprint`, then its override.
    /// On failure the override and the row stay, and `errorMessage` is set.
    func forget(_ fingerprint: String) async {
        guard let forgetCallback, forgetting == nil else { return }
        forgetting = fingerprint
        defer { forgetting = nil }
        do {
            try await forgetCallback(fingerprint)
        } catch {
            errorMessage = "Could not forget the passphrase for "
                + "\(KeyIdentifier.abbreviated(fingerprint)). "
                + "\(SavedPassphrases.failureReason(for: error)) "
                + "Nothing was removed."
            return
        }
        store.removeOverride(for: fingerprint)
        await load()
    }

    private func makeRow(_ fingerprint: String) -> Row {
        Row(
            fingerprint: fingerprint,
            policy: store.policy(for: fingerprint),
            hasOverride: store.override(for: fingerprint) != nil
        )
    }

    private func replaceRow(_ fingerprint: String) {
        guard let index = rows.firstIndex(where: { $0.fingerprint == fingerprint }) else { return }
        rows[index] = makeRow(fingerprint)
    }
}

/// Formatting for the hex identifiers that key the Keychain entries.
enum KeyIdentifier {

    /// Upper-case hex in groups of four: `ABCD 1234 …`.
    static func grouped(_ fingerprint: String) -> String {
        let upper = Array(fingerprint.uppercased())
        return stride(from: 0, to: upper.count, by: 4)
            .map { String(upper[$0..<min($0 + 4, upper.count)]) }
            .joined(separator: " ")
    }

    /// First and last eight hex characters, e.g. `ABCD1234…89ABCDEF`.
    static func abbreviated(_ fingerprint: String) -> String {
        let upper = fingerprint.uppercased()
        guard upper.count > 20 else { return upper }
        return "\(upper.prefix(8))…\(upper.suffix(8))"
    }
}

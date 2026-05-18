// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// PerKeyPolicyView.swift — Settings → Per-Key tab.
//
// Lists each fingerprint that currently has a cached entry in the
// data-protection keychain, plus a "Default for new keys" section at the
// top. Each row exposes:
//
//   - Biometry requirement (Picker)
//   - Accessibility class (Picker)
//   - Cache TTL (Stepper)
//   - Forget button (calls back to the executable which deletes the
//     keychain entry AND removes the per-key override)
//
// The enumeration query uses `kSecUseAuthenticationUISkip` so opening
// Settings never fires a Touch ID sheet — only the per-key Forget action
// triggers an unlock prompt (because SecItemDelete on a `.userPresence`
// entry can prompt, depending on user posture).
//
// Persistence: writes go through `KeyPolicyStore` immediately on toggle
// change. There is no Save button — that matches the rest of Settings.

import SwiftUI
import KeychainStore

public struct PerKeyPolicyView: View {

    /// Optional callback to delete an entry's keychain row. Provided by
    /// the executable so the view does not need to import a clear-by-
    /// fingerprint API directly. nil disables the Forget button.
    public typealias ForgetCallback = @Sendable (String) async -> Void

    private let store: KeyPolicyStore
    private let service: String
    private let useDataProtectionKeychain: Bool
    private let forget: ForgetCallback?

    /// Re-enumerated on appear and after Forget. Sorted lexically so
    /// rows are stable across refreshes.
    @State private var fingerprints: [String] = []
    /// Bumped to force per-row policy reads after a save. Cheap because
    /// the underlying store is a JSON-in-UserDefaults lookup.
    @State private var refreshTick = 0
    @State private var defaultPolicy: KeyPolicy = .legacyDefault

    public init(
        store: KeyPolicyStore = KeyPolicyStore(),
        service: String = "GnuPG",
        useDataProtectionKeychain: Bool = true,
        forget: ForgetCallback? = nil
    ) {
        self.store = store
        self.service = service
        self.useDataProtectionKeychain = useDataProtectionKeychain
        self.forget = forget
    }

    public var body: some View {
        Form {
            Section("Default for new keys") {
                policyEditor(
                    title: "Default",
                    policy: defaultPolicy,
                    onChange: { updated in
                        defaultPolicy = updated
                        store.setDefaultPolicy(updated)
                    }
                )
                Text("Applied when you tick \"Save in Keychain\" for a key that has no per-key override.")
                    .font(Theme.captionFont)
                    .foregroundStyle(Color.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            if fingerprints.isEmpty {
                Section("Saved keys") {
                    Text("No cached passphrases yet. Save one from a pinentry dialog and it will appear here.")
                        .font(Theme.captionFont)
                        .foregroundStyle(Color.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            } else {
                ForEach(fingerprints, id: \.self) { fpr in
                    Section(displayFingerprint(fpr)) {
                        // refreshTick forces a re-read whenever a sibling
                        // row's save bumps it; without it SwiftUI would
                        // cache the original closure-captured policy.
                        let _ = refreshTick
                        let row = store.policy(for: fpr)
                        let hasOverride = store.override(for: fpr) != nil

                        policyEditor(
                            title: fpr,
                            policy: row,
                            onChange: { updated in
                                store.setPolicy(updated, for: fpr)
                                refreshTick &+= 1
                            }
                        )

                        HStack {
                            if hasOverride {
                                Button("Reset to default") {
                                    store.removeOverride(for: fpr)
                                    refreshTick &+= 1
                                }
                            }
                            Spacer()
                            if let forget {
                                Button(role: .destructive) {
                                    Task { @MainActor in
                                        await forget(fpr)
                                        store.removeOverride(for: fpr)
                                        refresh()
                                    }
                                } label: {
                                    Text("Forget this key")
                                        .foregroundStyle(Theme.errorText)
                                }
                            }
                        }
                    }
                }
            }
        }
        .padding(Theme.mediumPadding)
        .onAppear {
            defaultPolicy = store.defaultPolicy
            refresh()
        }
    }

    // MARK: - Subviews

    @ViewBuilder
    private func policyEditor(
        title: String,
        policy: KeyPolicy,
        onChange: @escaping (KeyPolicy) -> Void
    ) -> some View {
        // SwiftUI Picker bindings work on the policy fields directly.
        Picker("Authentication", selection: Binding(
            get: { policy.biometry },
            set: { onChange(KeyPolicy(biometry: $0,
                                      accessibility: policy.accessibility,
                                      cacheTTLSeconds: policy.cacheTTLSeconds)) }
        )) {
            Text("Touch ID or passcode").tag(KeyPolicy.BiometryRequirement.userPresence)
            Text("Biometry (current set)").tag(KeyPolicy.BiometryRequirement.biometryCurrentSet)
            Text("Biometry (any enrolled)").tag(KeyPolicy.BiometryRequirement.biometryAny)
            Text("Passcode only").tag(KeyPolicy.BiometryRequirement.devicePasscode)
        }
        .pickerStyle(.menu)

        Picker("Accessibility", selection: Binding(
            get: { policy.accessibility },
            set: { onChange(KeyPolicy(biometry: policy.biometry,
                                      accessibility: $0,
                                      cacheTTLSeconds: policy.cacheTTLSeconds)) }
        )) {
            Text("When unlocked").tag(KeyPolicy.Accessibility.whenUnlocked)
            Text("When passcode is set").tag(KeyPolicy.Accessibility.whenPasscodeSet)
        }
        .pickerStyle(.menu)

        Picker("Cache duration", selection: Binding(
            get: { policy.cacheTTLSeconds ?? 0 },
            set: { newValue in
                let ttl: Int? = newValue == 0 ? nil : newValue
                onChange(KeyPolicy(biometry: policy.biometry,
                                   accessibility: policy.accessibility,
                                   cacheTTLSeconds: ttl))
            }
        )) {
            Text("Until cleared").tag(0)
            Text("5 minutes").tag(5 * 60)
            Text("1 hour").tag(60 * 60)
            Text("8 hours").tag(8 * 60 * 60)
            Text("1 day").tag(24 * 60 * 60)
        }
        .pickerStyle(.menu)
    }

    // MARK: - Helpers

    private func refresh() {
        fingerprints = KeychainEnumerator.fingerprints(
            service: service,
            useDataProtectionKeychain: useDataProtectionKeychain
        )
    }

    /// Display a fingerprint as `0x` + first 16 hex chars (matches the
    /// format gpg uses for the short key id) so the row header is human-
    /// scannable. The full fingerprint is the actual record key.
    private func displayFingerprint(_ fpr: String) -> String {
        let upper = fpr.uppercased()
        if upper.count >= 16 {
            return "0x" + String(upper.prefix(16))
        }
        return "0x" + upper
    }
}

// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// SecureEnclaveWrap.swift — Tier 3 of the validation remediation plan.
//
// What this adds
// --------------
// Passphrases stored in the data-protection keychain are now wrapped under
// a per-fingerprint P-256 ECDH key resident in the Secure Enclave (SE).
// The wrap key is generated lazily on first store and persisted as
// CryptoKit's opaque `dataRepresentation` (an SE-encrypted handle, safe to
// store anywhere — only the same SE can unwrap it).
//
// What this defends against
// --------------------------
// Pre-Tier-3, a keychain dump from a same-user attacker who has coerced
// the `.userPresence` prompt yields plaintext. Post-Tier-3 the attacker
// must additionally coerce the SE chip into performing ECDH against a
// biometric-gated key — kernel-level access to the keychain alone is no
// longer sufficient.
//
// Blob layout (stored as the keychain entry's `kSecValueData`)
// -------------------------------------------------------------
//   offset  length  field
//   0       1       version byte (0x01 = SE-wrapped v1)
//   1       65      ephemeral P-256 public key, X9.63 uncompressed
//                   (starts with 0x04; that second-byte check is the
//                    cheap legacy-vs-wrapped discriminator)
//   66      ≥28     AES-GCM SealedBox.combined: nonce(12) || ct(N) || tag(16)
//
// Total = 94 + N bytes for an N-byte plaintext.
//
// Detection of legacy entries (pinentry-mac, pre-Tier-3 pinentry-darwin):
//   first byte == 0x01 AND second byte == 0x04 → wrapped.
//   Anything else → legacy unwrapped passphrase.
// A human-typed UTF-8 passphrase whose first two bytes are exactly
// SOH + EOT is essentially impossible; binary passphrases that happen to
// start with that pair would be misinterpreted (acceptable: pinentry's
// own GETPIN flow produces only UTF-8 passphrases).
//
// Per-fingerprint SE key storage
// ------------------------------
// One SE key per GPG fingerprint, persisted to UserDefaults under
// `SEWrapKey/<fingerprint-lower>` as the `dataRepresentation` bytes.
// Stored in UserDefaults rather than the keychain because the
// representation is itself SE-encrypted; it carries no secret material
// that would benefit from keychain ACL protection.
//
// Lifecycle
// ---------
//   - CLEARPASSPHRASE (or per-key Forget) → delete the SE key + clear the
//     wrap-rep so re-cache generates a fresh key.
//   - Biometric re-enrollment (with policy = biometryCurrentSet) → the
//     SE chip invalidates the key. Unwrap fails with cryptoKitError or
//     authenticationFailed → caller treats as cache miss + cleans up.
//   - Migration Assistant → SE keys do not transfer; the
//     dataRepresentation is opaque to the destination SE. Unwrap fails;
//     caller treats as cache miss + cleans up.
//   - Pre-T2 Intel Macs (no SE) → `isAvailable` reports false; the
//     wrap path falls back to writing the passphrase unwrapped (legacy
//     layout). The `.userPresence` ACL on the keychain entry is the
//     only protection in this mode.

import Foundation
import CryptoKit
import LocalAuthentication
import Security
import SecureMemory
import os

private let log = Logger(
    subsystem: "org.whitworth.pinentry-darwin",
    category: "se-wrap"
)

// MARK: - Errors

public enum SecureEnclaveWrapError: Error, Equatable {
    case enclaveUnavailable
    case malformedBlob
    case unsupportedVersion(UInt8)
    case generationFailed(String)
    case keyAgreementFailed(String)
    case sealedBoxFailed(String)
    case missingWrapKey
    /// AES-GCM tag verification failed — typically biometric mismatch,
    /// SE key invalidation, or wrong wrap key for this fingerprint.
    /// Callers treat this as a cache miss + cleanup.
    case authenticationFailed
}

// MARK: - SEWrapKeyStore

/// Persists CryptoKit `SecureEnclave.P256.KeyAgreement.PrivateKey`
/// `dataRepresentation` per fingerprint. The bytes are themselves
/// SE-encrypted (only the same SE chip can use them), so they need no
/// additional keychain ACL — UserDefaults is sufficient and avoids a
/// second keychain row per fingerprint.
public struct SEWrapKeyStore: @unchecked Sendable {

    private static let prefix = "SEWrapKey/"
    private let defaults: UserDefaults

    public init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    public func loadDataRepresentation(fingerprint: String) -> Data? {
        defaults.data(forKey: Self.key(for: fingerprint))
    }

    public func store(dataRepresentation: Data, fingerprint: String) {
        defaults.set(dataRepresentation, forKey: Self.key(for: fingerprint))
    }

    public func remove(fingerprint: String) {
        defaults.removeObject(forKey: Self.key(for: fingerprint))
    }

    private static func key(for fingerprint: String) -> String {
        prefix + fingerprint.lowercased()
    }
}

// MARK: - SecureEnclaveWrap

public enum SecureEnclaveWrap {

    /// Magic / version byte of the wrap blob. Bumped on any layout change.
    public static let currentVersion: UInt8 = 0x01

    /// X9.63 uncompressed point marker. The first byte of any
    /// `SecureEnclave.P256.PublicKey.x963Representation`. Used as the
    /// second-byte discriminator that says "this is a wrapped blob, not
    /// a passphrase that happens to start with 0x01."
    private static let x963Uncompressed: UInt8 = 0x04

    /// HKDF info parameter — bumped on any KDF / cipher change.
    private static let hkdfInfo = "pinentry-darwin-wrap-v1".data(using: .utf8)!

    /// Public-key byte length for P-256 X9.63 uncompressed: 1 + 32 + 32.
    private static let pubKeyBytes = 65

    /// `true` on every Mac with a usable Secure Enclave (Apple Silicon
    /// and post-2017 Intel with T2). Cached after first call.
    public static var isAvailable: Bool {
        SecureEnclave.isAvailable
    }

    // MARK: Wire format helpers

    /// Quick discriminator: does `blob` carry our version + X9.63 marker?
    /// `false` means treat as a legacy unwrapped passphrase.
    public static func isWrapped(_ blob: Data) -> Bool {
        blob.count >= 2
            && blob[blob.startIndex] == currentVersion
            && blob[blob.index(after: blob.startIndex)] == x963Uncompressed
    }

    // MARK: Wrap

    /// Wrap `passphrase` under the per-fingerprint SE key. Generates the
    /// key if absent.
    ///
    /// `policy` selects the SE key's `SecAccessControl` flags via the
    /// same KeyPolicy → flags mapping used by the keychain entry, so a
    /// single LAContext can unlock both within
    /// `touchIDAuthenticationAllowableReuseDuration` (10 s).
    ///
    /// Throws `enclaveUnavailable` on hardware without an SE — the
    /// caller falls back to non-wrapped storage.
    public static func wrap(
        passphrase: SecureBytes,
        fingerprint: String,
        policy: KeyPolicy,
        store: SEWrapKeyStore = SEWrapKeyStore()
    ) throws -> Data {
        guard isAvailable else { throw SecureEnclaveWrapError.enclaveUnavailable }

        // SecureBytes inits precondition-fail on zero-capacity input, so
        // `passphrase.withUnsafeBytes` here is guaranteed to receive a
        // non-nil base and a positive count. The seal-step force-unwrap
        // is safe under that invariant.

        // 1. Load or generate the SE key.
        let seKey = try loadOrGenerateWrapKey(
            fingerprint: fingerprint,
            policy: policy,
            store: store
        )
        let sePublic = seKey.publicKey

        // 2. Ephemeral software P-256 keypair for the wrap operation.
        //    No SE involvement — pure software ECDH on the wrapping
        //    side; only unwrap needs the SE.
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let ephemeralPubBytes = ephemeral.publicKey.x963Representation
        guard ephemeralPubBytes.count == pubKeyBytes,
              ephemeralPubBytes[0] == x963Uncompressed
        else {
            throw SecureEnclaveWrapError.generationFailed(
                "unexpected ephemeral pubkey length \(ephemeralPubBytes.count)"
            )
        }

        // 3. ECDH(ephemeral private, SE public). Software-only.
        let shared: SharedSecret
        do {
            shared = try ephemeral.sharedSecretFromKeyAgreement(with: sePublic)
        } catch {
            throw SecureEnclaveWrapError.keyAgreementFailed(String(describing: error))
        }

        // 4. HKDF-SHA256(shared, salt = SE public key bytes, info).
        //    Salting with the SE public key binds the derived key to this
        //    specific SE key instance — a different SE key (same KDF
        //    params) produces a different AES key.
        let saltData = sePublic.x963Representation
        let aesKey = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: saltData,
            sharedInfo: hkdfInfo,
            outputByteCount: 32
        )

        // 5. AES-GCM seal. CryptoKit picks a random 12-byte nonce.
        //    Bridge the SecureBytes buffer to Data via `bytesNoCopy` with
        //    a `.none` deallocator so Foundation does not allocate a
        //    separate (un-mlock'd, un-zeroed) heap copy of the plaintext.
        //    SecureBytes owns the memory; `pt` is a view only. CryptoKit
        //    may still copy internally for its own scratch buffer — that
        //    copy is outside our control and is the residual SL-2 risk.
        let sealed = try passphrase.withUnsafeBytes { (buf: UnsafeBufferPointer<UInt8>) -> AES.GCM.SealedBox in
            // step-0 above guarantees baseAddress non-nil and count > 0.
            let base = buf.baseAddress!
            do {
                let mutable = UnsafeMutableRawPointer(mutating: UnsafeRawPointer(base))
                let pt = Data(bytesNoCopy: mutable, count: buf.count, deallocator: .none)
                return try AES.GCM.seal(pt, using: aesKey)
            } catch {
                throw SecureEnclaveWrapError.sealedBoxFailed(String(describing: error))
            }
        }
        guard let combined = sealed.combined else {
            throw SecureEnclaveWrapError.sealedBoxFailed("SealedBox.combined returned nil")
        }

        // 6. Assemble blob: version(1) || ephPub(65) || combined(N+28).
        var out = Data(capacity: 1 + pubKeyBytes + combined.count)
        out.append(currentVersion)
        out.append(ephemeralPubBytes)
        out.append(combined)
        return out
    }

    // MARK: Unwrap

    /// Unwrap a blob produced by `wrap`. Returns nil on
    /// `authenticationFailed` (caller treats as cache miss and cleans up
    /// the stale SE key + keychain entry).
    public static func unwrap(
        blob: Data,
        fingerprint: String,
        context: LAContext,
        store: SEWrapKeyStore = SEWrapKeyStore()
    ) throws -> SecureBytes {
        guard isAvailable else { throw SecureEnclaveWrapError.enclaveUnavailable }

        // 1. Layout sanity. We need at least version + pubkey + AES-GCM
        //    overhead (12 nonce + 16 tag = 28).
        let minLen = 1 + pubKeyBytes + 28
        guard blob.count >= minLen else { throw SecureEnclaveWrapError.malformedBlob }
        guard blob[blob.startIndex] == currentVersion else {
            throw SecureEnclaveWrapError.unsupportedVersion(blob[blob.startIndex])
        }

        let pubStart = blob.index(blob.startIndex, offsetBy: 1)
        let pubEnd = blob.index(pubStart, offsetBy: pubKeyBytes)
        let ephPubBytes = blob[pubStart..<pubEnd]
        guard ephPubBytes.first == x963Uncompressed else {
            throw SecureEnclaveWrapError.malformedBlob
        }
        let combined = blob[pubEnd...]

        let ephPub: P256.KeyAgreement.PublicKey
        do {
            ephPub = try P256.KeyAgreement.PublicKey(x963Representation: ephPubBytes)
        } catch {
            throw SecureEnclaveWrapError.malformedBlob
        }

        // 2. Load the SE key for this fingerprint. Missing wrap key
        //    means: Migration-Assistant-ed keychain, manually deleted SE
        //    key, or first-time install with a pre-existing legacy entry.
        //    Surface as a distinct error so the caller can decide to
        //    treat as cache miss + cleanup.
        guard let rep = store.loadDataRepresentation(fingerprint: fingerprint) else {
            throw SecureEnclaveWrapError.missingWrapKey
        }

        let seKey: SecureEnclave.P256.KeyAgreement.PrivateKey
        do {
            seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                dataRepresentation: rep,
                authenticationContext: context
            )
        } catch {
            // dataRepresentation rejected — typically SE re-enrollment
            // invalidated the key, or the key was produced by a different
            // SE (Migration Assistant). Surface as authenticationFailed
            // so the caller cleans up.
            log.error("SE key load failed; treating as cache miss")
            throw SecureEnclaveWrapError.authenticationFailed
        }

        // 3. ECDH on the SE — THIS is where the biometric prompt fires
        //    (gated by the SecAccessControl baked into the SE key).
        //    The LAContext's `localizedReason` (set by AssuanLoop from
        //    SETDESC) is what the sheet displays.
        let shared: SharedSecret
        do {
            shared = try seKey.sharedSecretFromKeyAgreement(with: ephPub)
        } catch {
            log.error("SE ECDH failed; treating as auth failure")
            throw SecureEnclaveWrapError.authenticationFailed
        }

        // 4. Re-derive AES key. Salt must match wrap (SE public key bytes).
        let saltData = seKey.publicKey.x963Representation
        let aesKey = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: saltData,
            sharedInfo: hkdfInfo,
            outputByteCount: 32
        )

        // 5. AES-GCM open. Tag mismatch ⇒ authenticationFailed.
        let sealed: AES.GCM.SealedBox
        do {
            sealed = try AES.GCM.SealedBox(combined: combined)
        } catch {
            throw SecureEnclaveWrapError.malformedBlob
        }

        var plaintext: Data
        do {
            plaintext = try AES.GCM.open(sealed, using: aesKey)
        } catch {
            log.error("AES-GCM open failed; treating as auth failure")
            throw SecureEnclaveWrapError.authenticationFailed
        }

        // 6. Copy into SecureBytes and wipe the intermediate Data. The
        //    plaintext buffer Foundation hands us is not mlock'd and is
        //    not zeroed on dealloc; explicitly overwrite it with
        //    memset_s (volatile-safe) before returning so the plaintext
        //    residency window is bounded to this scope. CryptoKit may
        //    have made additional internal copies before returning — that
        //    is the documented residual SL-2 risk and matches the
        //    encrypt-side acceptance.
        defer {
            plaintext.withUnsafeMutableBytes { (raw: UnsafeMutableRawBufferPointer) in
                if let base = raw.baseAddress, raw.count > 0 {
                    _ = memset_s(base, raw.count, 0, raw.count)
                }
            }
        }
        let secure = plaintext.withUnsafeBytes { (raw: UnsafeRawBufferPointer) -> SecureBytes in
            let typed = raw.bindMemory(to: UInt8.self)
            return SecureBytes(copying: typed)
        }
        return secure
    }

    // MARK: SE key lifecycle

    /// Delete the per-fingerprint SE key. Idempotent. Call from the
    /// keychain `clear` path so a re-cache generates a fresh SE key.
    public static func deleteWrapKey(
        fingerprint: String,
        store: SEWrapKeyStore = SEWrapKeyStore()
    ) {
        store.remove(fingerprint: fingerprint)
    }

    // MARK: Internals

    /// Load the existing SE key for `fingerprint`, or generate + persist
    /// a new one. Generation itself does NOT prompt for biometry —
    /// the SecAccessControl gate fires only on use.
    ///
    /// CONCURRENCY: load-check-generate-store is not atomic. Two concurrent
    /// `wrap` calls for the same fingerprint can both observe a missing
    /// rep, both generate fresh SE keys, and have one silently overwrite
    /// the other in UserDefaults — orphaning the first SE key and making
    /// the first wrap blob undecryptable. This is acceptable because
    /// gpg-agent drives pinentry from a serial Assuan loop (one operation
    /// at a time per pinentry process), and Settings UI writes are
    /// serialized on the main actor. Callers that drive concurrent wraps
    /// for the same fingerprint MUST serialize externally.
    private static func loadOrGenerateWrapKey(
        fingerprint: String,
        policy: KeyPolicy,
        store: SEWrapKeyStore
    ) throws -> SecureEnclave.P256.KeyAgreement.PrivateKey {
        if let rep = store.loadDataRepresentation(fingerprint: fingerprint) {
            // Wrap path: no LAContext needed — the public-key extraction
            // does not require authentication.
            do {
                return try SecureEnclave.P256.KeyAgreement.PrivateKey(
                    dataRepresentation: rep
                )
            } catch {
                // Existing wrap-rep is invalid (re-enrollment, copied
                // from another Mac). Throw it away and generate fresh.
                log.error("existing SE wrap key invalid; regenerating")
                store.remove(fingerprint: fingerprint)
            }
        }

        // Generate. SecAccessControl built from KeyPolicy so unwrap
        // honours the user's chosen biometry tier.
        var cfError: Unmanaged<CFError>?
        guard let control = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            policy.secAccessibility,
            policy.secAccessControlFlags,
            &cfError
        ) else {
            let detail = cfError.map { String(describing: $0.takeRetainedValue()) }
                ?? "SecAccessControlCreateWithFlags returned nil"
            throw SecureEnclaveWrapError.generationFailed("access-control: \(detail)")
        }

        let key: SecureEnclave.P256.KeyAgreement.PrivateKey
        do {
            key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                accessControl: control
            )
        } catch {
            throw SecureEnclaveWrapError.generationFailed(String(describing: error))
        }
        store.store(dataRepresentation: key.dataRepresentation, fingerprint: fingerprint)
        log.info("generated SE wrap key for fingerprint=\(fingerprint, privacy: .private)")
        return key
    }
}

// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// PinViewModel.swift — `@Observable` view-model for `PinView`.
//
// IMPORTANT — String / SecureBytes boundary
// ------------------------------------------
// SwiftUI's `SecureField` and `TextField` are bound to `String`. We cannot
// avoid that residue with stock SwiftUI: the user types into a SwiftUI
// text-storage `String` and we observe `.onChange` to mirror the bytes
// into a `SecureBytes`. We do NOT keep the source `String` in the
// view-model; instead, on every change we:
//
//   1. take the new String's UTF-8 bytes,
//   2. reset and re-fill the `SecureBytes`,
//   3. let the SwiftUI text-storage `String` be replaced by the View's
//      `@State` on the next keystroke (we never read it back ourselves).
//
// We accept that the SwiftUI text storage may briefly hold a copy of the
// passphrase. For v1.0.0 this is the documented residual exposure. The
// `SecureBytes` is the authoritative copy that gets written to the
// Assuan wire.
//
// NOTE: There is no live quality bar. Each keystroke firing
// INQUIRE QUALITY at gpg-agent would be an additional transient
// exposure of the candidate bytes (wire → agent → estimator → wire),
// for the sake of a heuristic score that anchors users on bar-satisfying
// passphrases over memorable ones. The wire surface (`Session.inquireQuality`)
// remains in AssuanProtocol for future consumers; we just don't call it.

import Foundation
import Observation
import KeychainStore
import SecureMemory

@MainActor
@Observable
public final class PinViewModel {

    // MARK: - Stored secrets

    /// Authoritative passphrase storage. UI mirrors string bindings here.
    public let pin: SecureBytes

    /// Repeat-passphrase buffer; only read when `spec.repeatPrompt != nil`.
    public let repeatPin: SecureBytes

    // MARK: - Observable UI state

    public var showTyping: Bool
    public var saveToKeychain: Bool

    /// Length of the typed pin. The View uses this so it can render the
    /// "*"-mask placeholder without re-querying the SecureBytes.
    public var pinLength: Int = 0
    public var repeatLength: Int = 0

    /// Mismatch flag, recomputed on every change.
    public var pinsMatch: Bool = true

    /// Whether the spec asked for a repeat-passphrase confirmation. When
    /// false, `pinsMatch` is held true regardless of the repeat buffer
    /// (which won't be filled by the UI) so a normal GETPIN can submit
    /// the moment the user types one character.
    private let repeatRequired: Bool

    /// True between `submit()` being invoked and the coordinator's result
    /// callback returning. Drives a `ProgressView` on the OK button so
    /// users get visual feedback their click registered. Today the flow
    /// is synchronous so this state lasts only the duration of a
    /// callback hop; the affordance is here so a future async post-submit
    /// path (e.g. Keychain access taking a moment) doesn't require a UI
    /// rewrite.
    public var isSubmitting: Bool = false

    // MARK: - Dependencies

    /// Coordinator-supplied callback. Invoked at most once.
    private var onResult: ((DialogResult) -> Void)?

    // MARK: - Init

    public init(
        spec: DialogSpec,
        showTypingByDefault: Bool,
        saveByDefault: Bool,
        onResult: @escaping (DialogResult) -> Void
    ) {
        self.pin = SecureBytes(capacity: 1024)
        self.repeatPin = SecureBytes(capacity: 1024)
        self.showTyping = showTypingByDefault
        // KC-2 / FV-1: when the data-protection keychain has rejected this
        // process for missing entitlement, refuse to default the Save
        // checkbox to true even if the user's pref says so. The View
        // additionally `disable()`s the toggle and surfaces a caption.
        // We compute degraded-posture here at construction time; the flag
        // is monotonic per process so once flipped it never flips back.
        let degraded = KeychainStore.degradedPostureObserved
        self.saveToKeychain = spec.allowKeychainSave && saveByDefault && !degraded
        self.onResult = onResult
        self.repeatRequired = (spec.repeatPrompt != nil)
        // No repeat field present means "match" is implicitly true.
        self.pinsMatch = !self.repeatRequired
    }

    // MARK: - Input

    /// Replace the contents of `pin` with the UTF-8 bytes of `value`.
    /// Truncates if the value would exceed the buffer capacity.
    public func setPin(from value: String) {
        Self.copy(string: value, into: pin)
        pinLength = pin.count
        recomputeMatch()
    }

    public func setRepeat(from value: String) {
        Self.copy(string: value, into: repeatPin)
        repeatLength = repeatPin.count
        recomputeMatch()
    }

    // MARK: - Resolution

    /// Hand ownership of `pin` to the coordinator.
    ///
    /// CRITICAL: we do NOT wipe `pin` here. The egress buffer is consumed
    /// downstream — `AssuanLoop.handleGetPin` writes it to the wire (and
    /// optionally stores it) AFTER `coordinator.present` returns. Zeroing
    /// it here would hand the consumer an empty buffer. The egress `pin`
    /// is wiped by the consumer immediately after that final write; we
    /// wipe the never-egressed `repeatPin` here since nothing downstream
    /// reads it.
    public func submit() {
        guard !isSubmitting else { return }
        isSubmitting = true
        repeatPin.reset()
        deliver(.pin(pin, savedToKeychain: saveToKeychain))
    }

    public func cancel() {
        wipe()
        deliver(.canceled)
    }

    public func notConfirmed() {
        wipe()
        deliver(.notConfirmed)
    }

    public func windowClosed() {
        wipe()
        deliver(.windowClosed)
    }

    public func timedOut() {
        wipe()
        deliver(.timedOut)
    }

    /// Deterministically zero both passphrase buffers. Called on every
    /// non-egress terminal path (cancel / close / timeout). On the submit
    /// path the egress `pin` is NOT wiped here — its consumer owns the
    /// deterministic wipe after the wire write (see `submit()`).
    public func wipe() {
        pin.reset()
        repeatPin.reset()
    }

    private func deliver(_ result: DialogResult) {
        guard let cb = onResult else { return }
        onResult = nil
        cb(result)
    }

    /// True when OK should be enabled: at least one byte typed, and (if a
    /// repeat field is shown) the two buffers match byte-for-byte.
    public var canSubmit: Bool {
        pin.count > 0 && pinsMatch
    }

    // MARK: - Private helpers

    private func recomputeMatch() {
        // If the spec didn't ask for a repeat field, match is implicit.
        // Otherwise the buffers must be the same length and content.
        guard repeatRequired else {
            pinsMatch = true
            return
        }
        if repeatPin.count == 0 && pin.count == 0 {
            pinsMatch = true
            return
        }
        if pin.count != repeatPin.count {
            pinsMatch = false
            return
        }
        var equal: UInt8 = 0
        pin.withUnsafeBytes { a in
            repeatPin.withUnsafeBytes { b in
                let n = a.count
                for i in 0..<n {
                    equal |= a[i] ^ b[i]
                }
            }
        }
        pinsMatch = (equal == 0)
    }

    private static func copy(string value: String, into buffer: SecureBytes) {
        // Walk `value.utf8` directly into the SecureBytes. The previous
        // `Array(value.utf8)` materialised the bytes in regular Swift
        // heap (Array<UInt8> has no deinit-zero) — a second unwiped
        // copy in addition to the SwiftUI text-storage residue
        // documented at the top of this file. Iterating the UTF8View
        // is allocation-free; the only extra storage is what the
        // SecureBytes owns.
        buffer.reset()
        let cap = buffer.capacity
        var written = 0
        for byte in value.utf8 {
            if written >= cap { break }
            buffer.append(byte)
            written += 1
        }
    }
}


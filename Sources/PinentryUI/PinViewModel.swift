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
        self.saveToKeychain = spec.allowKeychainSave && saveByDefault
        self.onResult = onResult
        // No repeat field present means "match" is implicitly true.
        self.pinsMatch = (spec.repeatPrompt == nil)
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
    public func submit() {
        guard !isSubmitting else { return }
        isSubmitting = true
        deliver(.pin(pin, savedToKeychain: saveToKeychain))
    }

    public func cancel() {
        deliver(.canceled)
    }

    public func notConfirmed() {
        deliver(.notConfirmed)
    }

    public func windowClosed() {
        deliver(.windowClosed)
    }

    public func timedOut() {
        deliver(.timedOut)
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
        buffer.reset()
        let utf8 = Array(value.utf8)
        let n = min(utf8.count, buffer.capacity)
        if n == 0 { return }
        utf8.withUnsafeBufferPointer { full in
            let prefix = UnsafeBufferPointer(start: full.baseAddress, count: n)
            buffer.append(contentsOf: prefix)
        }
    }
}


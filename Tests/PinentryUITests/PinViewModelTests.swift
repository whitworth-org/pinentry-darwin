// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// PinViewModelTests.swift — pins the GETPIN data path end-to-end at the
// model layer (the boundary the SwiftUI view binds to).
//
// Why this exists: the View itself is hard to drive without UI tests, and
// regressions in the typing-→-submit path manifest as "the dialog doesn't
// accept input" or "OK never enables" — symptoms a user can only catch by
// running the binary. These tests prove the model side is sound, so when
// a user reports such a symptom we can localise the issue to the
// SwiftUI/AppKit boundary instead of the data flow.

import XCTest
@testable import PinentryUI

final class PinViewModelTests: XCTestCase {

    @MainActor
    func testCanSubmitFalseUntilPinTyped() {
        let spec = DialogSpec(kind: .pin)
        let model = PinViewModel(
            spec: spec,
            showTypingByDefault: false,
            saveByDefault: false,
            onResult: { _ in }
        )
        XCTAssertFalse(model.canSubmit, "empty pin must not be submittable")

        model.setPin(from: "x")
        XCTAssertTrue(model.canSubmit, "single character must enable submit")
    }

    // The OK button's "transition from dim to bright accent on first
    // character" affordance is wired off `model.canSubmit`. If this
    // invariant breaks, the visual transition stops firing.
    @MainActor
    func testCanSubmitFlipsOnFirstCharacterSynchronously() {
        let spec = DialogSpec(kind: .pin)
        let model = PinViewModel(
            spec: spec,
            showTypingByDefault: false,
            saveByDefault: false,
            onResult: { _ in }
        )
        XCTAssertFalse(model.canSubmit)
        model.setPin(from: "a")
        XCTAssertTrue(model.canSubmit)
        model.setPin(from: "")
        XCTAssertFalse(model.canSubmit, "clearing the field must dim OK again")
    }

    @MainActor
    func testSubmitDeliversTypedBytes() {
        let spec = DialogSpec(kind: .pin)
        var delivered: DialogResult?
        let model = PinViewModel(
            spec: spec,
            showTypingByDefault: false,
            saveByDefault: false,
            onResult: { delivered = $0 }
        )
        model.setPin(from: "correcthorsebatterystaple")
        model.submit()

        guard case .pin(let bytes, let saved) = delivered else {
            XCTFail("expected .pin result, got \(String(describing: delivered))")
            return
        }
        XCTAssertFalse(saved, "saveByDefault=false should not flip saved=true")
        let observed = bytes.withUnsafeBytes { Data($0) }
        XCTAssertEqual(observed, Data("correcthorsebatterystaple".utf8))
    }

    @MainActor
    func testCancelDeliversCanceled() {
        let spec = DialogSpec(kind: .pin)
        var delivered: DialogResult?
        let model = PinViewModel(
            spec: spec,
            showTypingByDefault: false,
            saveByDefault: false,
            onResult: { delivered = $0 }
        )
        model.setPin(from: "ignored")
        model.cancel()
        guard case .canceled = delivered else {
            XCTFail("expected .canceled, got \(String(describing: delivered))")
            return
        }
    }

    // The view-model promises onResult fires at most once. The
    // coordinator's Resolver also enforces this, but we want a tighter
    // invariant at the model layer in case anyone wires the model
    // directly (e.g. from a future UI test harness).
    @MainActor
    func testResultDeliveredAtMostOnce() {
        let spec = DialogSpec(kind: .pin)
        var deliveryCount = 0
        let model = PinViewModel(
            spec: spec,
            showTypingByDefault: false,
            saveByDefault: false,
            onResult: { _ in deliveryCount += 1 }
        )
        model.setPin(from: "x")
        model.submit()
        model.submit() // duplicate click; isSubmitting must guard
        model.cancel() // late cancel after submit also must not fire
        XCTAssertEqual(deliveryCount, 1)
    }

    @MainActor
    func testRepeatMismatchBlocksSubmit() {
        var spec = DialogSpec(kind: .pin)
        spec.repeatPrompt = "Repeat:"
        let model = PinViewModel(
            spec: spec,
            showTypingByDefault: false,
            saveByDefault: false,
            onResult: { _ in }
        )
        model.setPin(from: "alpha")
        model.setRepeat(from: "beta")
        XCTAssertFalse(model.pinsMatch)
        XCTAssertFalse(model.canSubmit, "mismatch must block submit")

        model.setRepeat(from: "alpha")
        XCTAssertTrue(model.pinsMatch)
        XCTAssertTrue(model.canSubmit)
    }

    @MainActor
    func testIsSubmittingFlipsOnSubmit() {
        let spec = DialogSpec(kind: .pin)
        let model = PinViewModel(
            spec: spec,
            showTypingByDefault: false,
            saveByDefault: false,
            onResult: { _ in }
        )
        XCTAssertFalse(model.isSubmitting)
        model.setPin(from: "x")
        model.submit()
        XCTAssertTrue(model.isSubmitting)
    }

    // MARK: - L-3: deterministic passphrase-buffer wipe on resolution

    // Cancel must zero BOTH buffers deterministically (not wait for
    // SecureBytes.deinit). After cancel the model's pin/repeatPin must
    // read empty.
    @MainActor
    func testCancelWipesBothBuffers() {
        var spec = DialogSpec(kind: .pin)
        spec.repeatPrompt = "Repeat:"
        let model = PinViewModel(
            spec: spec,
            showTypingByDefault: false,
            saveByDefault: false,
            onResult: { _ in }
        )
        model.setPin(from: "alpha")
        model.setRepeat(from: "alpha")
        XCTAssertGreaterThan(model.pin.count, 0)
        XCTAssertGreaterThan(model.repeatPin.count, 0)

        model.cancel()
        XCTAssertEqual(model.pin.count, 0, "cancel must zero the pin buffer")
        XCTAssertEqual(model.repeatPin.count, 0, "cancel must zero the repeat buffer")
    }

    @MainActor
    func testWindowClosedWipesBothBuffers() {
        let model = makeModel()
        model.setPin(from: "hunter2")
        XCTAssertGreaterThan(model.pin.count, 0)
        model.windowClosed()
        XCTAssertEqual(model.pin.count, 0, "close must zero the pin buffer")
        XCTAssertEqual(model.repeatPin.count, 0)
    }

    @MainActor
    func testTimedOutWipesBothBuffers() {
        let model = makeModel()
        model.setPin(from: "swordfish")
        XCTAssertGreaterThan(model.pin.count, 0)
        model.timedOut()
        XCTAssertEqual(model.pin.count, 0, "timeout must zero the pin buffer")
        XCTAssertEqual(model.repeatPin.count, 0)
    }

    // Submit must NOT wipe the egress `pin` buffer — its bytes are still
    // owned by the consumer (AssuanLoop writes them to the wire after
    // present() returns). It MUST, however, wipe the never-egressed
    // `repeatPin` since nothing downstream reads it.
    @MainActor
    func testSubmitPreservesEgressPinButWipesRepeat() {
        var spec = DialogSpec(kind: .pin)
        spec.repeatPrompt = "Repeat:"
        var delivered: DialogResult?
        let model = PinViewModel(
            spec: spec,
            showTypingByDefault: false,
            saveByDefault: false,
            onResult: { delivered = $0 }
        )
        model.setPin(from: "alpha")
        model.setRepeat(from: "alpha")
        model.submit()

        guard case .pin(let bytes, _) = delivered else {
            XCTFail("expected .pin result, got \(String(describing: delivered))")
            return
        }
        // Egress buffer is the model's own `pin`; it must still hold the
        // typed bytes so the consumer can write them to the wire.
        XCTAssertEqual(bytes.count, 5, "submit must NOT zero the egress pin buffer")
        let observed = bytes.withUnsafeBytes { Data($0) }
        XCTAssertEqual(observed, Data("alpha".utf8))
        // The repeat buffer never egresses, so submit zeros it immediately.
        XCTAssertEqual(model.repeatPin.count, 0, "submit must zero the repeat buffer")
    }

    // wipe() is idempotent and safe to call on already-empty buffers.
    @MainActor
    func testWipeIsIdempotent() {
        let model = makeModel()
        model.setPin(from: "x")
        model.wipe()
        XCTAssertEqual(model.pin.count, 0)
        model.wipe()
        XCTAssertEqual(model.pin.count, 0)
    }

    @MainActor
    private func makeModel() -> PinViewModel {
        PinViewModel(
            spec: DialogSpec(kind: .pin),
            showTypingByDefault: false,
            saveByDefault: false,
            onResult: { _ in }
        )
    }
}

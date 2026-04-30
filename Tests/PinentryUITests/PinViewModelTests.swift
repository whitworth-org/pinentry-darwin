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
    func testCanSubmitFlipsOnFirstCharacterSyncrhonously() {
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
}

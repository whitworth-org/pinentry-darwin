// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth
//
// SecureBytesTests — unit tests for the mlock'd, deinit-zeroed buffer.

import Darwin
import Foundation
import XCTest
@testable import SecureMemory

final class SecureBytesTests: XCTestCase {

    /// Copy of the valid prefix, read through the safe `Span` accessor.
    private func contents(of buf: SecureBytes) -> [UInt8] {
        buf.withSpan { span in (0..<span.count).map { span[$0] } }
    }

    // MARK: - Allocation / basic state

    func testAllocateInitialState() {
        let buf = SecureBytes(capacity: 64)
        XCTAssertEqual(buf.count, 0)
        XCTAssertEqual(buf.capacity, 64)
        XCTAssertTrue(buf.isEmpty)
    }

    func testCapacityRoundsUpToPageSize() {
        // The *logical* capacity reported to callers must be exactly what
        // they asked for, even though internally we round up to a page.
        // We can't directly observe `mappedBytes`, but we can confirm the
        // public API doesn't leak the rounding by reading back `capacity`.
        let pageSize = Int(getpagesize())
        XCTAssertGreaterThan(pageSize, 0)

        let small = SecureBytes(capacity: 1)
        XCTAssertEqual(small.capacity, 1, "logical capacity must equal requested")

        // Asking for exactly maxLength must not trap.
        let big = SecureBytes(capacity: SecureBytes.maxLength)
        XCTAssertEqual(big.capacity, SecureBytes.maxLength)
        XCTAssertEqual(big.count, 0)
    }

    func testRoundUpToPageHelper() {
        // Direct test of the helper used by the allocator. Page size is
        // always a power of two on supported Darwin hosts, so this verifies
        // the masking logic.
        let pageSize = Int(getpagesize())
        XCTAssertEqual(roundUpToPage(0, pageSize: pageSize), 0)
        XCTAssertEqual(roundUpToPage(1, pageSize: pageSize), pageSize)
        XCTAssertEqual(roundUpToPage(pageSize, pageSize: pageSize), pageSize)
        XCTAssertEqual(roundUpToPage(pageSize + 1, pageSize: pageSize), pageSize * 2)
        XCTAssertEqual(roundUpToPage(pageSize * 3 - 1, pageSize: pageSize), pageSize * 3)
    }

    // MARK: - Append

    func testAppendByteByByte() {
        let buf = SecureBytes(capacity: 8)
        let payload: [UInt8] = [0xDE, 0xAD, 0xBE, 0xEF]
        for b in payload {
            buf.append(b)
        }
        XCTAssertEqual(buf.count, payload.count)
        XCTAssertEqual(contents(of: buf), payload)
    }

    func testAppendBuffer() {
        let buf = SecureBytes(capacity: 16)
        let payload: [UInt8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        buf.append(contentsOf: payload.span)
        XCTAssertEqual(buf.count, payload.count)
        XCTAssertEqual(contents(of: buf), payload)
    }

    func testAppendEmptyBufferIsNoOp() {
        let buf = SecureBytes(capacity: 4)
        buf.append(0xAA)
        let empty: [UInt8] = []
        buf.append(contentsOf: empty.span)
        XCTAssertEqual(buf.count, 1)
        XCTAssertEqual(contents(of: buf), [0xAA])
    }

    // MARK: - init(copying:) / init([UInt8])

    func testInitCopyingBuffer() {
        let payload: [UInt8] = [0x10, 0x20, 0x30, 0x40, 0x50]
        let buf = SecureBytes(copying: payload.span)
        XCTAssertEqual(buf.count, payload.count)
        XCTAssertEqual(buf.capacity, payload.count)
        XCTAssertEqual(contents(of: buf), payload)
    }

    func testInitFromArray() {
        let payload: [UInt8] = [0xAA, 0xBB, 0xCC, 0xDD]
        let buf = SecureBytes(payload)
        XCTAssertEqual(buf.count, payload.count)
        XCTAssertEqual(buf.capacity, payload.count)
        XCTAssertEqual(contents(of: buf), payload)
    }

    // MARK: - reset

    func testResetZeroesContentAndCount() {
        let buf = SecureBytes(capacity: 32)
        // Write a recognisable sentinel pattern.
        let sentinel: [UInt8] = Array(repeating: 0xA5, count: 16)
        buf.append(contentsOf: sentinel.span)
        XCTAssertEqual(buf.count, 16)

        buf.reset()
        XCTAssertEqual(buf.count, 0)
        XCTAssertTrue(buf.isEmpty)

        // After reset the underlying bytes 0..<16 must read as zero. Use
        // the mutable accessor to peek (non-mutating peek through the
        // capacity-sized window).
        unsafe buf.withUnsafeMutableBytes { full in
            for i in 0..<16 {
                XCTAssertEqual(unsafe full[i], 0,
                               "byte \(i) should be zeroed after reset")
            }
        }
    }

    /// `withUnsafeMutableBytes` can write past `count`; `reset()` must wipe
    /// those bytes too, not just `0..<count`.
    func testResetZeroesBytesWrittenPastCount() {
        let buf = SecureBytes(capacity: 32)
        buf.append(0x01)
        unsafe buf.withUnsafeMutableBytes { full in
            for i in 0..<full.count { unsafe full[i] = 0xA5 }
        }

        buf.reset()

        unsafe buf.withUnsafeMutableBytes { full in
            XCTAssertEqual(unsafe Array(full), Array(repeating: 0, count: 32),
                           "reset() must wipe the whole capacity")
        }
    }

    func testResetOnEmptyIsNoOp() {
        let buf = SecureBytes(capacity: 8)
        buf.reset()
        XCTAssertEqual(buf.count, 0)
        XCTAssertTrue(buf.isEmpty)
    }

    func testCanReuseAfterReset() {
        let buf = SecureBytes(capacity: 8)
        buf.append(0x11)
        buf.append(0x22)
        buf.reset()
        buf.append(0x33)
        XCTAssertEqual(buf.count, 1)
        XCTAssertEqual(contents(of: buf), [0x33])
    }

    // MARK: - withUnsafeMutableBytes

    func testWithUnsafeMutableBytesExposesFullCapacity() {
        let buf = SecureBytes(capacity: 10)
        buf.append(0x01)
        unsafe buf.withUnsafeMutableBytes { full in
            XCTAssertEqual(full.count, 10)
            // Existing prefix preserved.
            XCTAssertEqual(unsafe full[0], 0x01)
            // Tail is kernel-zeroed.
            for i in 1..<10 {
                XCTAssertEqual(unsafe full[i], 0)
            }
        }
    }

    // MARK: - Overflow trap
    //
    // We can't directly XCTest a `fatalError` — it terminates the process.
    // The contract is: any write past `capacity` traps with a deterministic
    // message. We exercise the just-fits boundary instead and document the
    // overflow case as covered by code inspection plus the precondition
    // text. (A future enhancement could spawn a child process via
    // `Process` to verify the trap, but that's heavy for what the static
    // analyser can already see.)

    func testAppendExactlyToCapacitySucceeds() {
        let buf = SecureBytes(capacity: 4)
        for _ in 0..<4 {
            buf.append(0xFF)
        }
        XCTAssertEqual(buf.count, 4)
        XCTAssertEqual(contents(of: buf), [0xFF, 0xFF, 0xFF, 0xFF])
    }

    func testAppendBufferExactlyToCapacitySucceeds() {
        let buf = SecureBytes(capacity: 8)
        let half: [UInt8] = [1, 2, 3, 4]
        buf.append(contentsOf: half.span)
        buf.append(contentsOf: half.span)
        XCTAssertEqual(buf.count, 8)
        XCTAssertEqual(contents(of: buf), [1, 2, 3, 4, 1, 2, 3, 4])
    }

    // MARK: - mlock failure tolerance
    //
    // We cannot reliably trigger `mlock` failure from a unit test without
    // root or `RLIMIT_MEMLOCK` manipulation. The `wasLocked` flag is
    // best-effort: failure is silently absorbed and `deinit` simply skips
    // `munlock`. Verified by code inspection of `init(capacity:)` and
    // `deinit`. Intentionally no test here.

    // MARK: - Deinit zero invariant
    //
    // Reading the buffer after `deinit` is undefined behaviour (the pages
    // are unmapped). We therefore rely on the `#if DEBUG`-only side-channel
    // `lastDeinitWasZeroed`, which `deinit` sets *before* unmapping based
    // on a sample of the freshly wiped region.

    #if DEBUG
    func testDeinitZeroesBeforeFree() {
        SecureBytes.lastDeinit = SecureBytes.DeinitProbe()

        // Scope the buffer so its `deinit` runs at end of block.
        do {
            let buf = SecureBytes(capacity: 64)
            // Fill with a non-zero sentinel so the wipe is observable.
            for _ in 0..<64 { buf.append(0x5A) }
            _ = buf.debugDescription()
        }

        XCTAssertTrue(SecureBytes.lastDeinit.wasZeroed,
                      "deinit must zero the mapping before unmapping")
    }

    /// Full page-lifecycle invariant. Under normal test conditions on macOS
    /// the kernel grants `mlock`, so `deinit` should observe in order:
    ///   1. wipe (`wasZeroed`)
    ///   2. wasLocked == true
    ///   3. munlock returns success (`didMunlock == .some(true)`)
    ///   4. munmap returns success (`didMunmap`)
    ///
    /// This is the autonomous half of the leaks/vmmap acceptance criterion
    /// in CLAUDE.md — the manual half (open a dialog, dismiss, run `leaks`)
    /// still needs a human, but the underlying syscall chain is verified
    /// here on every CI run.
    func testDeinitFullLifecycle() {
        SecureBytes.lastDeinit = SecureBytes.DeinitProbe()

        do {
            let buf = SecureBytes(capacity: 128)
            for _ in 0..<128 { buf.append(0xA5) }
            // The instance has to be referenced after the writes so the
            // writes aren't optimised away; debugDescription is a no-op
            // touch that also asserts wasLocked at allocation time.
            XCTAssertTrue(buf.debugDescription().contains("locked: true"),
                          "fresh allocation should be mlock'd under default RLIMIT_MEMLOCK")
        }

        XCTAssertEqual(
            SecureBytes.lastDeinit,
            SecureBytes.DeinitProbe(
                wasZeroed: true, wasLocked: true, didMunlock: true, didMunmap: true
            ),
            "deinit must wipe, munlock, then munmap a locked region"
        )
    }
    #endif

    // MARK: - Concurrency

    /// `append` is documented as safe under contention: the count must
    /// never lose an increment or exceed capacity.
    func testConcurrentAppendsNeverLoseOrOverrunCount() {
        let appends = 4000
        let buf = SecureBytes(capacity: SecureBytes.maxLength)
        DispatchQueue.concurrentPerform(iterations: appends) { _ in
            buf.append(0x7F)
        }
        XCTAssertEqual(buf.count, appends)
        XCTAssertTrue(contents(of: buf).allSatisfy { $0 == 0x7F })
    }

    // MARK: - debugDescription doesn't leak content

    func testDebugDescriptionDoesNotIncludeBytes() {
        let buf = SecureBytes(capacity: 8)
        buf.append(0xDE)
        buf.append(0xAD)
        let desc = buf.debugDescription()
        XCTAssertTrue(desc.contains("count: 2"))
        XCTAssertTrue(desc.contains("capacity: 8"))
        // Spot-check that no obvious hex byte representation of our payload
        // leaked into the description.
        XCTAssertFalse(desc.lowercased().contains("de"),
                       "debug description must not include payload bytes")
        XCTAssertFalse(desc.lowercased().contains("ad"),
                       "debug description must not include payload bytes")
    }

    // MARK: - Sendable / no auto-print conformances

    func testNoCustomStringConvertibleConformance() {
        // If a future change accidentally adds CustomStringConvertible the
        // `String(describing:)` output would equal `description`. We
        // deliberately use the type-name fallback instead.
        let buf = SecureBytes(capacity: 4)
        buf.append(0xAB)
        let s = String(describing: buf)
        // Default Swift descriptor is something like
        // "SecureMemory.SecureBytes" — assert it does NOT contain "count:"
        // (which only `debugDescription()` produces).
        XCTAssertFalse(s.contains("count:"),
                       "SecureBytes must not conform to CustomStringConvertible")
    }
}

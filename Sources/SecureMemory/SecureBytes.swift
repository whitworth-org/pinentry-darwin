// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth
//
// SecureBytes — an mlock'd, deinit-zeroed byte buffer for passphrases and
// other secrets that must not survive the lifetime of the object that owns
// them. The ingress points are `[UInt8]` and `Span<UInt8>`; `Swift.String`
// is intentionally absent. The pointer-based entry points are `@unsafe`
// and kept only until their remaining callers move to `Span`.

import Darwin
import Synchronization

/// A heap buffer of bytes whose backing pages are allocated via `mmap`,
/// (best-effort) locked into physical memory via `mlock`, and explicitly
/// zeroed via `memset_s` on `deinit`.
///
/// ### Thread safety
///
/// The valid-byte count is guarded by a mutex, so concurrent `append` and
/// `reset` calls can never push `count` past `capacity` or write out of
/// bounds. Byte *contents* are not synchronised against a concurrent
/// reader: a `withSpan` borrow that overlaps an `append` or `reset` on
/// another thread may observe the bytes change, but never invalid memory.
/// Callers that need a stable view must serialise access themselves.
///
/// ### Caller responsibilities
///
/// - The convenience `init(_ bytes: [UInt8])` copies its input but cannot
///   wipe the caller's array, since `Array<UInt8>` is value-typed and the
///   caller still owns the storage. If the source bytes are sensitive the
///   caller must wipe them itself after constructing the `SecureBytes`.
/// - `append(_:)` and `append(contentsOf:)` will trap (`fatalError`) on
///   overflow rather than auto-growing — auto-grow would require copying
///   into a new mapping and could leave residue in the freed pages.
// SAFETY: `region` is created in `init`, never replaced, and unmapped only
// in `deinit`, so it is valid for the whole life of every method call. The
// only mutable state, `_count`, is behind a `Mutex` and is only ever set to
// a value in `0...capacity`, so every access through `region` is in
// bounds. Pointers never leave the type through a safe member.
@safe
public final class SecureBytes: @unchecked Sendable {

    /// Hard cap on the size of any single `SecureBytes` instance. PIN buffers
    /// in the Assuan protocol are line-bounded at 1000 bytes; 16 KiB is
    /// generous enough to cover repeat-passphrase scratch space and the
    /// `INQUIRE QUALITY` round-trip without ever growing into a region that
    /// would seriously dent `RLIMIT_MEMLOCK` on a stock macOS system.
    public static let maxLength: Int = 16 * 1024

    /// The whole mapping (`mappedBytes` long). Freed in `deinit`.
    private let region: UnsafeMutableBufferPointer<UInt8>
    /// Logical capacity (≤ `region.count`). What `append` bounds-checks against.
    private let _capacity: Int
    /// Number of valid bytes currently stored at `region[0..<count]`.
    private let _count = Mutex<Int>(0)
    /// Whether `mlock` succeeded. Drives whether `deinit` calls `munlock`.
    private let wasLocked: Bool

    // MARK: - Initialisers

    /// Allocate a buffer with the given logical capacity. Capacity is rounded
    /// up to the system page size for the actual mapping; the logical
    /// `capacity` accessor still reports the requested value.
    ///
    /// - Precondition: `0 < capacity <= SecureBytes.maxLength`.
    /// - Postcondition: `count == 0`, contents are zeroed (anonymous mmap is
    ///   kernel-zeroed on Darwin).
    public init(capacity: Int) {
        precondition(capacity > 0,
                     "SecureBytes capacity must be > 0")
        precondition(capacity <= SecureBytes.maxLength,
                     "SecureBytes capacity \(capacity) exceeds maxLength \(SecureBytes.maxLength)")

        let mapped = roundUpToPage(capacity, pageSize: Int(getpagesize()))

        // `mmap` failure is fatal — there's no graceful path: the rest of
        // this class assumes `region` is valid.
        let mapping: UnsafeMutableBufferPointer<UInt8>
        do {
            unsafe mapping = try secureMmap(bytes: mapped)
        } catch {
            fatalError("SecureBytes: \(error)")
        }

        // Best-effort lock; failure is acceptable. Common reasons:
        //   - RLIMIT_MEMLOCK exhausted (typical default on macOS is small).
        //   - sandboxed processes denied mlock by the kernel.
        // We continue rather than abort; the buffer is still mmap'd-anonymous
        // (so it isn't backed by any file) and will still be zeroed on deinit.
        self.wasLocked = secureMlock(mapping)
        unsafe self.region = mapping
        self._capacity = capacity
    }

    /// Copy `span` into a fresh `SecureBytes` whose capacity exactly matches
    /// the input length. The source is not wiped — the caller still owns it.
    ///
    /// - Precondition: `0 < span.count <= SecureBytes.maxLength`.
    public convenience init(copying span: Span<UInt8>) {
        precondition(span.count > 0,
                     "SecureBytes(copying:) requires a non-empty buffer")
        precondition(span.count <= SecureBytes.maxLength,
                     "SecureBytes(copying:) input length \(span.count) exceeds "
                     + "maxLength \(SecureBytes.maxLength)")
        self.init(capacity: span.count)
        append(contentsOf: span)
    }

    /// Copy the bytes of `buffer`. Prefer `init(copying: Span<UInt8>)`.
    ///
    /// - Precondition: `buffer` is valid for `buffer.count` bytes, and
    ///   `0 < buffer.count <= SecureBytes.maxLength`.
    @unsafe
    public convenience init(copying buffer: UnsafeBufferPointer<UInt8>) {
        self.init(copying: unsafe Span(_unsafeElements: buffer))
    }

    /// Convenience: copy a `[UInt8]`. The array's storage is **not** wiped —
    /// `Array<UInt8>` is value-typed and the caller still owns it. If the
    /// input is sensitive, wipe it explicitly after this initialiser returns.
    public convenience init(_ bytes: [UInt8]) {
        self.init(capacity: bytes.count)
        append(contentsOf: bytes.span)
    }

    // MARK: - Public accessors

    /// Number of valid bytes currently stored. Mutates via `append` / `reset`.
    public var count: Int { _count.withLock { $0 } }

    /// Logical capacity in bytes (the value passed to `init(capacity:)` or
    /// the length of the source for `init(copying:)`).
    public var capacity: Int { _capacity }

    /// `true` iff `count == 0`.
    public var isEmpty: Bool { count == 0 }

    // MARK: - Mutation

    /// Append a single byte. Traps if there is no capacity left — auto-grow
    /// would leak residue into freed pages.
    public func append(_ byte: UInt8) {
        _count.withLock { count in
            guard count < _capacity else {
                fatalError("SecureBytes overflow: capacity=\(_capacity), count=\(count), wanted=1")
            }
            unsafe region[count] = byte
            count += 1
        }
    }

    /// Append the contents of `bytes`. Traps on overflow (see `append`).
    public func append(contentsOf bytes: Span<UInt8>) {
        let n = bytes.count
        if n == 0 { return }
        _count.withLock { count in
            guard n <= _capacity - count else {
                fatalError(
                    "SecureBytes overflow: capacity=\(_capacity), count=\(count), wanted=\(n)")
            }
            for i in 0..<n {
                unsafe region[count + i] = bytes[i]
            }
            count += n
        }
    }

    /// Append the contents of `bytes`. Traps on overflow (see `append`).
    /// Prefer `append(contentsOf: Span<UInt8>)`.
    ///
    /// - Precondition: `bytes` is valid for `bytes.count` bytes.
    @unsafe
    public func append(contentsOf bytes: UnsafeBufferPointer<UInt8>) {
        append(contentsOf: unsafe Span(_unsafeElements: bytes))
    }

    /// Zero the whole logical capacity and reset `count` to zero. The
    /// mapping is reused. The full capacity is wiped, not just `0..<count`,
    /// so bytes written past `count` through `withUnsafeMutableBytes` do
    /// not survive.
    public func reset() {
        _count.withLock { count in
            unsafe secureZero(UnsafeMutableBufferPointer(rebasing: region[0..<_capacity]))
            count = 0
        }
    }

    // MARK: - Borrowed access

    /// Borrow the valid prefix as a `Span` for the duration of `body`. The
    /// span cannot escape the closure.
    public func withSpan<R>(_ body: (Span<UInt8>) throws -> R) rethrows -> R {
        let valid = count
        let span = unsafe Span(_unsafeElements: UnsafeBufferPointer(rebasing: region[0..<valid]))
        return try body(span)
    }

    // MARK: - Unsafe access

    /// Borrow the valid prefix as an immutable buffer pointer for the
    /// duration of `body`. Do not retain the pointer past the call.
    /// Prefer `withSpan`.
    @unsafe
    public func withUnsafeBytes<R>(
        _ body: (UnsafeBufferPointer<UInt8>) throws -> R
    ) rethrows -> R {
        let valid = count
        let buf = unsafe UnsafeBufferPointer(rebasing: region[0..<valid])
        return try unsafe body(buf)
    }

    /// Borrow the *full* capacity as a mutable buffer pointer for the
    /// duration of `body`. The caller is responsible for not writing past
    /// `capacity`; `count` is not adjusted by this method.
    @unsafe
    public func withUnsafeMutableBytes<R>(
        _ body: (UnsafeMutableBufferPointer<UInt8>) throws -> R
    ) rethrows -> R {
        let buf = unsafe UnsafeMutableBufferPointer(rebasing: region[0..<_capacity])
        return try unsafe body(buf)
    }

    // MARK: - Debug

    /// A safe (non-leaking) description for diagnostics. Deliberately does
    /// **not** conform to `CustomStringConvertible` — we don't want it
    /// appearing in `print`/`String(describing:)` by accident.
    public func debugDescription() -> String {
        "SecureBytes(count: \(count), capacity: \(_capacity), locked: \(wasLocked))"
    }

    #if DEBUG
    /// What the most recent `deinit` observed. Debug-only; the test suite
    /// uses it to verify the wipe-unlock-unmap sequence, because the pages
    /// cannot be inspected once they are unmapped. **Never read or set this
    /// in non-test code.**
    public struct DeinitProbe: Sendable, Equatable {
        /// The first bytes of the mapping read back as zero after the wipe.
        public var wasZeroed = false
        /// `wasLocked` at the moment of deinit.
        public var wasLocked = false
        /// Whether `munlock` succeeded; `nil` if the buffer was never locked.
        public var didMunlock: Bool?
        /// Whether `munmap` succeeded.
        public var didMunmap = false
    }

    private static let deinitProbe = Mutex(DeinitProbe())

    /// The probe written by the most recent `deinit`. Assign a fresh
    /// `DeinitProbe()` before a test to clear it.
    public static var lastDeinit: DeinitProbe {
        get { deinitProbe.withLock { $0 } }
        set { deinitProbe.withLock { $0 = newValue } }
    }
    #endif

    // MARK: - Cleanup

    deinit {
        // Always wipe before unlocking/unmapping. `memset_s` cannot be
        // dead-store-eliminated even though `self` is going away. We wipe
        // the entire mapped region (not just `count`) so any residue from
        // earlier appends is gone before the pages are returned to the
        // kernel.
        unsafe secureZero(region)

        #if DEBUG
        // Verify the wipe happened by reading back the first bytes. If
        // `memset_s` were optimised away (it shouldn't be), this would
        // observe non-zero data.
        let wasZeroed = unsafe region.prefix(64).allSatisfy { $0 == 0 }
        #endif

        let didMunlock = unsafe wasLocked ? secureMunlock(region) : nil
        let didMunmap = unsafe secureMunmap(region)

        #if DEBUG
        let probe = DeinitProbe(
            wasZeroed: wasZeroed,
            wasLocked: wasLocked,
            didMunlock: didMunlock,
            didMunmap: didMunmap
        )
        SecureBytes.lastDeinit = probe
        #endif
    }
}

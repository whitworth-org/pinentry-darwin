// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth
//
// SecureBytes — an mlock'd, deinit-zeroed byte buffer for passphrases and
// other secrets that must not survive the lifetime of the object that owns
// them. The single ingress points are `[UInt8]` and
// `UnsafeBufferPointer<UInt8>`; `Swift.String` is intentionally absent.

import Darwin
import Foundation

/// A heap buffer of bytes whose backing pages are allocated via `mmap`,
/// (best-effort) locked into physical memory via `mlock`, and explicitly
/// zeroed via `memset_s` on `deinit`.
///
/// ### Thread safety
///
/// `SecureBytes` is **not** thread-safe. It is marked `@unchecked Sendable`
/// purely so it can be passed across actor boundaries by the rest of the
/// codebase; any concurrent access to the same instance must be externally
/// synchronised by the caller.
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
public final class SecureBytes: @unchecked Sendable {

    /// Hard cap on the size of any single `SecureBytes` instance. PIN buffers
    /// in the Assuan protocol are line-bounded at 1000 bytes; 16 KiB is
    /// generous enough to cover repeat-passphrase scratch space and the
    /// `INQUIRE QUALITY` round-trip without ever growing into a region that
    /// would seriously dent `RLIMIT_MEMLOCK` on a stock macOS system.
    public static let maxLength: Int = 16 * 1024

    /// Backing mapping. Always non-nil for the lifetime of the instance;
    /// freed in `deinit`.
    private let ptr: UnsafeMutableRawPointer
    /// Number of bytes mapped — always a multiple of the system page size and
    /// `>= requested capacity`.
    private let mappedBytes: Int
    /// Logical capacity (≤ `mappedBytes`). What `append` bounds-checks against.
    private let _capacity: Int
    /// Number of valid bytes currently stored at `ptr[0..<count]`.
    private var _count: Int
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

        let pageSize = Int(getpagesize())
        let mapped = roundUpToPage(capacity, pageSize: pageSize)

        // `mmap` failure is fatal — there's no graceful path: the rest of
        // this class assumes `ptr` is valid for `mappedBytes`.
        let raw: UnsafeMutableRawPointer
        do {
            raw = try secureMmap(bytes: mapped)
        } catch {
            fatalError("SecureBytes: \(error)")
        }

        // Best-effort lock; failure is acceptable. Common reasons:
        //   - RLIMIT_MEMLOCK exhausted (typical default on macOS is small).
        //   - sandboxed processes denied mlock by the kernel.
        // We continue rather than abort; the buffer is still mmap'd-anonymous
        // (so it isn't backed by any file) and will still be zeroed on deinit.
        self.wasLocked = secureMlock(raw, bytes: mapped)

        self.ptr = raw
        self.mappedBytes = mapped
        self._capacity = capacity
        self._count = 0
    }

    /// Copy `bytes` into a fresh `SecureBytes` whose capacity exactly matches
    /// the input length. The source buffer is not wiped — the caller still
    /// owns it.
    public init(copying bytes: UnsafeBufferPointer<UInt8>) {
        precondition(bytes.count > 0,
                     "SecureBytes(copying:) requires a non-empty buffer")
        precondition(bytes.count <= SecureBytes.maxLength,
                     "SecureBytes(copying:) input length \(bytes.count) exceeds maxLength \(SecureBytes.maxLength)")

        let pageSize = Int(getpagesize())
        let mapped = roundUpToPage(bytes.count, pageSize: pageSize)

        let raw: UnsafeMutableRawPointer
        do {
            raw = try secureMmap(bytes: mapped)
        } catch {
            fatalError("SecureBytes: \(error)")
        }

        self.wasLocked = secureMlock(raw, bytes: mapped)
        self.ptr = raw
        self.mappedBytes = mapped
        self._capacity = bytes.count
        self._count = bytes.count

        // Copy the source bytes into the freshly mapped region. Anonymous
        // mmap pages are zero-filled, so the tail (if `mapped > count`)
        // already reads as zero.
        if let base = bytes.baseAddress {
            raw.copyMemory(from: UnsafeRawPointer(base), byteCount: bytes.count)
        }
    }

    /// Convenience: copy a `[UInt8]`. The array's storage is **not** wiped —
    /// `Array<UInt8>` is value-typed and the caller still owns it. If the
    /// input is sensitive, wipe it explicitly after this initialiser returns.
    public convenience init(_ bytes: [UInt8]) {
        // `Array.withUnsafeBufferPointer` synchronously hands us a buffer
        // whose lifetime is the closure's; calling `init(copying:)` inside
        // the closure copies its contents before we return. Swift's two-
        // phase init permits delegating to another `init` from a closure.
        let secure = bytes.withUnsafeBufferPointer { buf -> SecureBytes in
            SecureBytes(copying: buf)
        }
        // Adopt `secure`'s storage: copy the same logical bytes into a new
        // mapping owned by `self`. We can't reuse `secure`'s mapping (would
        // require non-trivial ownership transfer); instead just re-copy.
        // The temporary `secure` is wiped on its own deinit at end of init.
        self.init(capacity: secure._capacity)
        secure.withUnsafeBytes { src in
            self.append(contentsOf: src)
        }
    }

    // MARK: - Public accessors

    /// Number of valid bytes currently stored. Mutates via `append` / `reset`.
    public var count: Int { _count }

    /// Logical capacity in bytes (the value passed to `init(capacity:)` or
    /// the length of the source buffer for `init(copying:)`).
    public var capacity: Int { _capacity }

    /// `true` iff `count == 0`.
    public var isEmpty: Bool { _count == 0 }

    // MARK: - Mutation

    /// Append a single byte. Traps if there is no capacity left — auto-grow
    /// would leak residue into freed pages.
    public func append(_ byte: UInt8) {
        if _count >= _capacity {
            fatalError("SecureBytes overflow: capacity=\(_capacity), count=\(_count), wanted=1")
        }
        ptr.storeBytes(of: byte, toByteOffset: _count, as: UInt8.self)
        _count += 1
    }

    /// Append the contents of `bytes`. Traps on overflow (see `append`).
    public func append(contentsOf bytes: UnsafeBufferPointer<UInt8>) {
        let n = bytes.count
        if n == 0 { return }
        if _count + n > _capacity {
            fatalError("SecureBytes overflow: capacity=\(_capacity), count=\(_count), wanted=\(n)")
        }
        if let base = bytes.baseAddress {
            (ptr + _count).copyMemory(from: UnsafeRawPointer(base), byteCount: n)
        }
        _count += n
    }

    /// Zero the bytes `0..<count` and reset `count` to zero. Capacity is
    /// unchanged; the mapping is reused.
    public func reset() {
        if _count > 0 {
            secureZero(ptr, bytes: _count)
        }
        _count = 0
    }

    // MARK: - Unsafe access

    /// Borrow the valid prefix as an immutable buffer pointer for the
    /// duration of `body`. Do not retain the pointer past the call.
    public func withUnsafeBytes<R>(
        _ body: (UnsafeBufferPointer<UInt8>) throws -> R
    ) rethrows -> R {
        let typed = ptr.bindMemory(to: UInt8.self, capacity: _capacity)
        let buf = UnsafeBufferPointer<UInt8>(start: typed, count: _count)
        return try body(buf)
    }

    /// Borrow the *full* capacity as a mutable buffer pointer for the
    /// duration of `body`. The caller is responsible for not writing past
    /// `capacity`; `count` is not adjusted by this method.
    public func withUnsafeMutableBytes<R>(
        _ body: (UnsafeMutableBufferPointer<UInt8>) throws -> R
    ) rethrows -> R {
        let typed = ptr.bindMemory(to: UInt8.self, capacity: _capacity)
        let buf = UnsafeMutableBufferPointer<UInt8>(start: typed, count: _capacity)
        return try body(buf)
    }

    // MARK: - Debug

    /// A safe (non-leaking) description for diagnostics. Deliberately does
    /// **not** conform to `CustomStringConvertible` — we don't want it
    /// appearing in `print`/`String(describing:)` by accident.
    public func debugDescription() -> String {
        "SecureBytes(count: \(_count), capacity: \(_capacity), locked: \(wasLocked))"
    }

    #if DEBUG
    /// Debug-only hook the test suite uses to verify that `deinit` actually
    /// called `secureZero` before unmapping. Set to `true` immediately after
    /// the wipe in `deinit`. **Never read or set this in non-test code.**
    public nonisolated(unsafe) static var lastDeinitWasZeroed: Bool = false
    /// Debug-only hook recording whether `munlock` succeeded in `deinit`.
    /// `nil` if the buffer was never locked (best-effort `mlock` failure).
    public nonisolated(unsafe) static var lastDeinitDidMunlock: Bool? = nil
    /// Debug-only hook recording whether `munmap` succeeded in `deinit`.
    public nonisolated(unsafe) static var lastDeinitDidMunmap: Bool = false
    /// Debug-only hook recording the most recent value of `wasLocked` at
    /// the moment the instance was deinit'd. Used by tests that don't keep
    /// the instance alive long enough to query `debugDescription()`.
    public nonisolated(unsafe) static var lastDeinitWasLocked: Bool = false
    #endif

    // MARK: - Cleanup

    deinit {
        // Always wipe before unlocking/unmapping. `memset_s` cannot be
        // dead-store-eliminated even though `self` is going away. We wipe
        // the entire mapped region (not just `count`) so any residue from
        // earlier appends or from the source buffer in `init(copying:)` is
        // gone before the pages are returned to the kernel.
        secureZero(ptr, bytes: mappedBytes)

        #if DEBUG
        // Verify the wipe happened by reading back a byte. If `memset_s`
        // were optimised away (it shouldn't be), this would observe
        // non-zero data. Probe up to 64 bytes.
        var allZero = true
        let probe = min(mappedBytes, 64)
        for i in 0..<probe {
            if ptr.load(fromByteOffset: i, as: UInt8.self) != 0 {
                allZero = false
                break
            }
        }
        SecureBytes.lastDeinitWasZeroed = allZero
        #endif

        #if DEBUG
        SecureBytes.lastDeinitWasLocked = wasLocked
        #endif

        if wasLocked {
            let unlocked = secureMunlock(ptr, bytes: mappedBytes)
            #if DEBUG
            SecureBytes.lastDeinitDidMunlock = unlocked
            #endif
        } else {
            #if DEBUG
            SecureBytes.lastDeinitDidMunlock = nil
            #endif
        }
        let unmapped = secureMunmap(ptr, bytes: mappedBytes)
        #if DEBUG
        SecureBytes.lastDeinitDidMunmap = unmapped
        #endif
    }
}

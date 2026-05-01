// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth
//
// Locking.swift — thin wrappers around the POSIX/Darwin syscalls used by
// `SecureBytes`: `mmap`, `mlock`, `munlock`, `munmap`, and the C11 Annex K
// `memset_s` (which the optimiser is forbidden from eliminating).
//
// All wrappers report failure via `errno`. The mlock wrapper additionally
// emits a one-shot os_log warning on the first failure so a host where
// RLIMIT_MEMLOCK is exhausted does not silently page secrets to swap.

import Darwin
import Foundation
import os

/// Process-wide logger for the secure-memory subsystem. Used only on
/// failure paths; the success path stays silent.
private let secureLogger = Logger(
    subsystem: "org.whitworth.pinentry-darwin",
    category: "secure"
)

/// One-shot guard so we emit at most one mlock-failure log per process.
/// Once mlock starts failing (RLIMIT_MEMLOCK exhausted, kernel denial,
/// sandbox), subsequent SecureBytes allocations will keep failing the
/// same way — flooding the log adds no diagnostic value.
private let mlockWarnFlag = OSAllocatedUnfairLock<Bool>(initialState: false)

/// Errors thrown by the page-level allocator. `mmap` failure is the only fatal
/// one — without a backing buffer there is nothing the caller can do.
enum SecureAllocError: Error, CustomStringConvertible {
    case mmapFailed(errno: Int32)

    var description: String {
        switch self {
        case .mmapFailed(let e):
            return "mmap failed (errno=\(e))"
        }
    }
}

/// Round `size` up to the nearest multiple of `pageSize`. `pageSize` must be a
/// power of two (true on every supported Darwin/macOS host today;
/// `getpagesize()` is 16384 on Apple Silicon).
@inline(__always)
func roundUpToPage(_ size: Int, pageSize: Int) -> Int {
    precondition(pageSize > 0 && (pageSize & (pageSize - 1)) == 0,
                 "pageSize must be a positive power of two")
    // Guard against overflow when `size` is pathologically large. The caller
    // (`SecureBytes.init`) already caps `capacity` to `maxLength`, so this is
    // belt-and-braces.
    let mask = pageSize - 1
    let (sum, overflow) = size.addingReportingOverflow(mask)
    precondition(!overflow, "size + pageSize-1 overflowed Int")
    return sum & ~mask
}

/// Allocate `bytes` of anonymous, private, read/write memory via `mmap`. The
/// returned pointer is page-aligned and the region is zero-filled by the
/// kernel (anonymous mappings are guaranteed zeroed on Darwin).
///
/// - Parameter bytes: must already be a multiple of the page size.
/// - Returns: a pointer to the start of the mapping.
/// - Throws: `SecureAllocError.mmapFailed` if the kernel refuses.
func secureMmap(bytes: Int) throws -> UnsafeMutableRawPointer {
    precondition(bytes > 0, "secureMmap requires a positive byte count")
    let raw = mmap(
        nil,
        bytes,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANON,
        -1,
        0
    )
    // `mmap` returns MAP_FAILED ((void *)-1) on error, not nil.
    if raw == MAP_FAILED {
        throw SecureAllocError.mmapFailed(errno: errno)
    }
    guard let raw else {
        // Defensive — Darwin's `mmap` should never return nil on success, but
        // the Swift overlay types it as optional. Treat nil as failure.
        throw SecureAllocError.mmapFailed(errno: errno)
    }
    return raw
}

/// Unmap a region previously returned by `secureMmap`. Returns `true` on
/// success. The caller has already wiped/unlocked the region.
@discardableResult
func secureMunmap(_ ptr: UnsafeMutableRawPointer, bytes: Int) -> Bool {
    return munmap(ptr, bytes) == 0
}

/// SL-4: when `PINENTRY_DARWIN_REQUIRE_MLOCK=1` is set in the environment,
/// the process aborts on the first mlock failure rather than continuing
/// with non-locked secret pages. Default off to preserve the M5 best-
/// effort contract; opt in for hardened deployments where leaving any
/// secret swap-eligible is unacceptable. Cached at module-init time so
/// repeated lookups don't pay the syscall cost.
private let strictMlockMode: Bool = {
    if let v = getenv("PINENTRY_DARWIN_REQUIRE_MLOCK"),
       let s = String(validatingUTF8: v) {
        return s == "1" || s.lowercased() == "true" || s.lowercased() == "yes"
    }
    return false
}()

/// Best-effort `mlock`. Returns `true` if the kernel locked the region into
/// physical memory (preventing it from being written to swap). `false` means
/// the lock failed — typically `EPERM` (no privileges) or `ENOMEM`
/// (RLIMIT_MEMLOCK exhausted). Callers should record the result so `deinit`
/// only `munlock`s a region that was actually locked.
///
/// On the FIRST failure per process, emits a single os_log warning so an
/// operator can correlate "secrets paged to swap" with the underlying
/// resource-limit condition. Subsequent failures stay silent unless
/// `PINENTRY_DARWIN_REQUIRE_MLOCK=1` is set, in which case the process
/// `abort()`s before any secret bytes can be written to a non-locked page.
func secureMlock(_ ptr: UnsafeMutableRawPointer, bytes: Int) -> Bool {
    let ok = mlock(ptr, bytes) == 0
    if !ok {
        let lockErr = errno
        let alreadyWarned = mlockWarnFlag.withLock { state -> Bool in
            let was = state
            state = true
            return was
        }
        if !alreadyWarned {
            secureLogger.error(
                "mlock failed (errno=\(lockErr, privacy: .public)); secret pages may be written to swap. Raise RLIMIT_MEMLOCK or run with elevated privileges."
            )
        }
        if strictMlockMode {
            secureLogger.fault(
                "PINENTRY_DARWIN_REQUIRE_MLOCK=1 set and mlock failed (errno=\(lockErr, privacy: .public)); aborting before secret bytes can land in non-locked memory."
            )
            // SIGABRT (consistent crash-reporter signal). RLIMIT_CORE=0
            // set by main.swift suppresses any core dump.
            abort()
        }
    }
    return ok
}

/// Counterpart to `secureMlock`. Returns `true` on success. Callers should
/// only invoke this when `secureMlock` previously returned `true`.
@discardableResult
func secureMunlock(_ ptr: UnsafeMutableRawPointer, bytes: Int) -> Bool {
    return munlock(ptr, bytes) == 0
}

/// Wipe `bytes` starting at `ptr` to zero. Uses `memset_s` so that the
/// optimiser cannot eliminate the write as a dead store (which a plain
/// `memset` is allowed to do once the buffer goes out of scope).
///
/// `memset_s` is part of C11 Annex K and is implemented in Darwin's libc.
@inline(never)
func secureZero(_ ptr: UnsafeMutableRawPointer, bytes: Int) {
    // The first two args are dest + destsz; the last two are the fill byte
    // (cast to Int32 / `int`) and the count. Both sizes are the same here.
    _ = memset_s(ptr, bytes, 0, bytes)
}

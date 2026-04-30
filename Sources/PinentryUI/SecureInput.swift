// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// SecureInput.swift — wrapper around Carbon's `EnableSecureEventInput` /
// `DisableSecureEventInput` (HIToolbox). When active, macOS routes
// keyboard events through a privileged path that other processes cannot
// observe, and shows a lock badge in the menu bar.
//
// Why a wrapper:
//   - Both Carbon calls are refcounted by the kernel per-process. The
//     wrapper maintains its own count so we can debug a leak (e.g. an
//     onAppear without a matching onDisappear) and so callers don't
//     accidentally underflow by calling disable() too many times.
//   - SwiftUI's lifecycle is well-behaved but not absolute — re-renders
//     of the view body don't fire onAppear, but a re-attached view tree
//     could. Counting prevents an unbalanced state from sticking.
//   - Provides a single place to observe/log SKE state for tests.
//
// Why Carbon:
//   - Apple's first-party apps (Keychain Access, Terminal, etc.) use the
//     same Carbon entry points. There is no AppKit-native replacement on
//     current macOS; the underlying IOHIDEventSystem APIs require
//     entitlements we don't have.
//
// Side-effects of activation:
//   - VoiceOver loses keyboard event broadcasting. Acceptable trade-off
//     for passphrase entry; matches Apple's own Keychain prompt.
//   - Most input methods (IMEs) won't work. ASCII-passphrase users
//     unaffected; non-ASCII passphrases are rare.
//   - The macOS auto-recovery on process termination guarantees SKE
//     drops to zero when our process exits, even if we crashed mid-
//     dialog. Defensive disable on resolve is still cheaper than a
//     stuck lock badge.

import AppKit
import Carbon.HIToolbox

@MainActor
public enum SecureInput {

    /// Per-process count of pending `enable()`s that have not yet had a
    /// matching `disable()`. Read-only externally for diagnostics.
    public private(set) static var refCount: Int = 0

    /// `true` when SKE is currently active (refCount > 0).
    public static var isActive: Bool { refCount > 0 }

    /// Enable secure event input. Returns true on success. Each call must
    /// be balanced by `disable()`. Calls are refcounted by the kernel,
    /// so multiple enables nest correctly.
    @discardableResult
    public static func enable() -> Bool {
        let status = EnableSecureEventInput()
        if status == noErr {
            refCount += 1
            return true
        }
        return false
    }

    /// Disable secure event input. Returns true on success. Refuses to
    /// underflow our local refCount even if disable() is called more
    /// times than enable() — the kernel-level count would still go to
    /// zero, so the underlying state is consistent.
    @discardableResult
    public static func disable() -> Bool {
        let status = DisableSecureEventInput()
        if status == noErr {
            // Defensive against unbalanced calls — keep the refCount
            // floor at 0 so callers can read it as "is at least one
            // outstanding enable still expected".
            if refCount > 0 { refCount -= 1 }
            return true
        }
        return false
    }

    /// Drop refCount to zero by issuing as many `disable()`s as needed.
    /// For use in process-termination signal handlers and test teardown.
    /// Returns the number of disables actually emitted.
    @discardableResult
    public static func reset() -> Int {
        var emitted = 0
        while refCount > 0 {
            if !disable() { break }
            emitted += 1
        }
        return emitted
    }
}

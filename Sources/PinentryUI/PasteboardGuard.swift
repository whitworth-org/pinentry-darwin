// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// PasteboardGuard — opportunistic cleanup of the general pasteboard when
// the user paste-fills a passphrase into the secure field.
//
// Threat model: users commonly paste passphrases from a password manager.
// After GETPIN returns, the cleartext remains on `NSPasteboard.general`
// until something else writes to it — minutes to hours, sometimes
// indefinitely on a screen-shared / RDP-style session where the
// pasteboard is rebroadcast.
//
// Mechanism: on focus-enter the caller snapshots `changeCount`. On
// submit, if the count advanced (i.e. a paste — or any other write —
// occurred during the entry window) AND the user has not opted out,
// we clear the pasteboard. This is intentionally conservative:
//   - we do NOT inspect pasteboard contents (which would itself read
//     the secret out of the system clipboard);
//   - we do NOT proactively poll changeCount on every keystroke;
//   - we do NOT clear on cancel — the user may have copied something
//     unrelated and we'd surprise them.

import AppKit
import os

@MainActor
public enum PasteboardGuard {

    private static let log = Logger(
        subsystem: "org.whitworth.pinentry-darwin",
        category: "pasteboard-guard"
    )

    /// Read the current pasteboard `changeCount`. Call when the secure
    /// field gains focus. The returned value is opaque; pass it back to
    /// ``clearIfAdvanced(since:enabled:on:)`` on submit.
    ///
    /// The `pasteboard` parameter defaults to `NSPasteboard.general`; tests
    /// pass a uniquely-named pasteboard to avoid touching the user's
    /// clipboard during automated runs.
    public static func snapshot(of pasteboard: NSPasteboard = .general) -> Int {
        pasteboard.changeCount
    }

    /// Clear `pasteboard` iff `enabled` is true AND the change count has
    /// advanced past `baseline`. Returns true when a clear was emitted.
    /// Idempotent / safe to call multiple times.
    @discardableResult
    public static func clearIfAdvanced(
        since baseline: Int,
        enabled: Bool,
        on pasteboard: NSPasteboard = .general
    ) -> Bool {
        guard enabled else { return false }
        let current = pasteboard.changeCount
        guard current > baseline else { return false }
        pasteboard.clearContents()
        log.info("cleared pasteboard after paste-fill (advanced \(current - baseline, privacy: .public) writes)")
        return true
    }
}

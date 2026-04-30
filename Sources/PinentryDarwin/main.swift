// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// main.swift — top-level entry point for the pinentry-darwin binary.
//
// Responsibilities:
//   1. Parse argv into a RuntimeMode (daemon / preferences / version / help).
//   2. Install signal handlers so SIGTERM/SIGHUP/SIGINT exit cleanly and
//      SIGPIPE doesn't crash us when gpg-agent closes its end of the pipe.
//   3. Bootstrap the appropriate mode:
//      - daemon:      activation policy .accessory (no Dock icon), AppDelegate
//                     handles stdio Assuan loop.
//      - preferences: activation policy .regular  (Dock icon), Settings window.
//      - version/help: print and exit.

import AppKit
import Darwin
import Foundation

// MARK: - Signal handlers

/// Install termination signal handlers. We do not attempt graceful shutdown
/// (zeroing live SecureBytes etc.) because:
///   - SecureBytes pages are mlock+anonymous-mmap, so the kernel returns
///     them to a free-zeroed pool when the process exits.
///   - The Swift runtime's signal-context restrictions make any "zero on
///     exit" path inherently racy. `_exit` is the safest reaction.
///
/// SIGPIPE is ignored so that the first failed write after gpg-agent dies
/// surfaces as an EPIPE the Session can translate into an EOF, rather than
/// abruptly terminating the process before it can log the cause.
@MainActor
private func installSignalHandlers() {
    signal(SIGPIPE, SIG_IGN)

    let terminator: @convention(c) (Int32) -> Void = { _ in
        // Best-effort: flush stderr before exiting. _exit avoids running
        // atexit / static destructors which is the right call here — we
        // do not want any code path that could touch the pasteboard or
        // any AppKit global from a signal context.
        _exit(1)
    }
    signal(SIGTERM, terminator)
    signal(SIGHUP, terminator)
    signal(SIGINT, terminator)

    // Surface uncaught NSExceptions on stderr before AppKit converts
    // them to SIGTRAP and kills us. AppKit's default behaviour is to
    // crash silently from a constraint-update path, which makes
    // diagnosis impossible from a release binary.
    NSSetUncaughtExceptionHandler { exc in
        var msg = "pinentry-darwin: uncaught NSException: "
        msg += exc.name.rawValue
        if let reason = exc.reason { msg += ": \(reason)" }
        msg += "\n"
        for frame in exc.callStackSymbols { msg += "  \(frame)\n" }
        if let data = msg.data(using: .utf8) {
            try? FileHandle.standardError.write(contentsOf: data)
        }
    }
}

// MARK: - Bootstrap

/// Print `text` to standard output without any logger involvement.
@MainActor
private func writeStdout(_ text: String) {
    if let data = text.data(using: .utf8) {
        try? FileHandle.standardOutput.write(contentsOf: data)
    }
}

@MainActor
private func bootstrap() -> Never {
    // Zero the core-dump rlimit before anything that might allocate a
    // SecureBytes runs. mlock(2) prevents swap but does NOT inhibit core
    // capture, so a crash mid-dialog without this line would dump live
    // passphrase pages (and any String escape residue) to /cores/. Must
    // be the first call so any panic from subsequent setup still hits a
    // {0,0} limit.
    var noCore = rlimit(rlim_cur: 0, rlim_max: 0)
    _ = setrlimit(RLIMIT_CORE, &noCore)

    // Try to raise the memlock soft limit toward 1 MiB so SecureBytes
    // can mlock its mappings. The macOS default for unprivileged
    // processes (and whatever gpg-agent inherits to us) is typically
    // tiny — when it's exhausted, SecureBytes silently allocates
    // anonymous-but-unlocked pages and secrets become swap-eligible.
    // Best-effort: failure is non-fatal (Locking.swift logs once on
    // the first mlock that doesn't take).
    var memlim = rlimit(rlim_cur: 0, rlim_max: 0)
    if getrlimit(RLIMIT_MEMLOCK, &memlim) == 0 {
        memlim.rlim_cur = min(memlim.rlim_max, rlim_t(1 << 20))
        _ = setrlimit(RLIMIT_MEMLOCK, &memlim)
    }

    installSignalHandlers()

    let mode = parseArgs(CommandLine.arguments)

    switch mode {
    case .version:
        writeStdout("pinentry-darwin \(resolvedVersion())\n")
        exit(0)

    case .help:
        writeStdout(helpText())
        exit(0)

    case .preferences:
        PreferencesMode.run()
        exit(0)

    case .daemon:
        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)
        let delegate = AppDelegate()
        // Strong reference — NSApplication only weakly holds its delegate.
        // Stash on a static so it survives until process exit.
        DelegateHolder.daemon = delegate
        app.delegate = delegate
        app.run()
        exit(0)
    }
}

// MARK: - Globals

/// Strong-reference holder for the daemon AppDelegate. NSApplication keeps
/// only a weak pointer to its delegate; without this the delegate would be
/// deallocated and `applicationDidFinishLaunching` would never fire.
@MainActor
enum DelegateHolder {
    static var daemon: AppDelegate?
}

// MARK: - Entry

bootstrap()

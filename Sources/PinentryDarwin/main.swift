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

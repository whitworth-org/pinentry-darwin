// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// RuntimeMode.swift — argv parsing for the pinentry-darwin executable.
//
// gpg-agent invokes us with no arguments (or a few benign legacy ones such as
// `--no-global-grab`, `--display=...`, `-D N`, etc.). We tolerate all of those
// so a future gpg-agent that adds new flags doesn't bring us down. Anything we
// don't recognise is logged to stderr but ignored — see comment in `parseArgs`.

import Foundation

// MARK: - RuntimeMode

/// What `main.swift` should do once argv has been parsed.
enum RuntimeMode: Equatable {
    /// Default: run as the Assuan agent, talking to gpg-agent over stdio.
    case daemon
    /// `--preferences`: open the SwiftUI Settings window as a foreground app.
    case preferences
    /// `--version` / `-V`: print version and exit 0.
    case version
    /// `--help` / `-h`: print one-line usage and exit 0.
    case help
}

// MARK: - parseArgs

/// Parse the executable's argv. Tolerant: unknown flags are reported to stderr
/// but do **not** trigger an exit, since gpg-agent occasionally adds new
/// pass-through arguments that older pinentry binaries are expected to ignore.
///
/// `argv[0]` (the program name) is dropped before processing.
func parseArgs(_ argv: [String]) -> RuntimeMode {
    let args = argv.dropFirst()
    var mode: RuntimeMode = .daemon

    var i = args.startIndex
    while i < args.endIndex {
        let arg = args[i]

        // Mode-changing flags.
        if arg == "--version" || arg == "-V" {
            return .version
        }
        if arg == "--help" || arg == "-h" {
            return .help
        }
        if arg == "--preferences" {
            mode = .preferences
            i = args.index(after: i)
            continue
        }

        // Silently-accepted legacy / pass-through flags from gpg-agent. The
        // option semantics duplicate later OPTION lines, so we don't need
        // their values; we just consume them to keep `unknown option` noise
        // out of the log.
        if arg == "--no-global-grab" || arg == "--parent-wid" {
            i = args.index(after: i)
            continue
        }

        // `--key=value` style pass-throughs.
        if arg.hasPrefix("--display=")
            || arg.hasPrefix("--ttyname=")
            || arg.hasPrefix("--ttytype=")
            || arg.hasPrefix("--lc-ctype=")
            || arg.hasPrefix("--lc-messages=")
            || arg.hasPrefix("--debug=")
            || arg.hasPrefix("--xauthority=")
            || arg.hasPrefix("--owner=")
            || arg.hasPrefix("--default-ok=")
            || arg.hasPrefix("--default-cancel=")
            || arg.hasPrefix("--default-prompt=")
        {
            i = args.index(after: i)
            continue
        }

        // `-D N` and `-T name` (debug-level / ttyname shorthand). Each
        // consumes one extra argv element if available.
        if arg == "-D" || arg == "-T" {
            i = args.index(after: i)
            if i < args.endIndex {
                i = args.index(after: i)
            }
            continue
        }

        // `--key value` style pass-throughs (separated form).
        if arg == "--display"
            || arg == "--ttyname"
            || arg == "--ttytype"
            || arg == "--lc-ctype"
            || arg == "--lc-messages"
            || arg == "--debug"
            || arg == "--xauthority"
            || arg == "--owner"
            || arg == "--default-ok"
            || arg == "--default-cancel"
            || arg == "--default-prompt"
        {
            i = args.index(after: i)
            if i < args.endIndex {
                i = args.index(after: i)
            }
            continue
        }

        // Unknown — warn but keep going. gpg-agent has historically added new
        // flags that older pinentry binaries are expected to ignore rather
        // than fail. Output goes to stderr (FD 2) so it doesn't pollute the
        // Assuan stdout stream.
        if let data = "pinentry-darwin: unknown option \(arg)\n".data(using: .utf8) {
            try? FileHandle.standardError.write(contentsOf: data)
        }
        i = args.index(after: i)
    }

    return mode
}

// MARK: - Version / help text

/// Resolve the marketing version string. Falls back to "0.1.0" when running
/// outside a bundle (e.g. `swift run`).
func resolvedVersion() -> String {
    if let v = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String,
       !v.isEmpty {
        return v
    }
    return "0.1.0"
}

/// Usage banner printed by `--help`.
func helpText() -> String {
    """
    usage: pinentry-darwin [--version] [--help] [--preferences]

    pinentry-darwin is a Swift 6 / SwiftUI replacement for pinentry-mac.
    Drop-in passphrase dialog for gpg-agent on macOS.

    Modes:
      (default)        Speak Assuan over stdin/stdout. Invoked by gpg-agent.
      --preferences    Open the Settings window as a foreground app.
      --version, -V    Print the version string and exit.
      --help, -h       Print this message and exit.

    Configure gpg-agent to use this binary by adding the following line
    to ~/.gnupg/gpg-agent.conf and running `gpgconf --kill gpg-agent`:

      pinentry-program /opt/homebrew/bin/pinentry-darwin

    See https://github.com/whitworth/pinentry-darwin for full docs.

    """
}

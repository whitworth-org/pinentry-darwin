// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// AppDelegate.swift — daemon-mode NSApplicationDelegate. Wires up the Assuan
// session over stdio, builds the coordinator, and spawns the protocol loop.
// On loop completion we tell NSApp to terminate so the process exits cleanly.

import AppKit
import Foundation
import os
import AssuanProtocol
import KeychainStore
import PinentryUI

private let log = Logger(subsystem: "org.whitworth.pinentry-darwin",
                         category: "appdelegate")

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {

    private var assuanLoop: AssuanLoop?

    func applicationDidFinishLaunching(_ notification: Notification) {
        // stdio bound to gpg-agent's pipes. We do NOT close stderr; it is
        // useful for debugging unknown-arg warnings.
        let stdin = FileHandle.standardInput
        let stdout = FileHandle.standardOutput

        let session = Session(input: stdin, output: stdout)

        // The coordinator reads UI settings (theme, etc.) from the store each
        // time it presents a dialog, so Settings changes apply to the next
        // dialog without restarting this process.
        let prefs = UserPrefs()
        let keychain = KeychainStore()

        Task { @MainActor in
            let coordinator = PinentryCoordinator(userPrefs: prefs)
            let loop = AssuanLoop(session: session,
                                  coordinator: coordinator,
                                  keychain: keychain,
                                  prefs: prefs)
            self.assuanLoop = loop
            await loop.run()
            log.info("assuan loop exited; terminating app")
            NSApp.terminate(nil)
        }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        // We're an LSUIElement-style accessory; the modal pinentry window
        // closing should NOT bring down the process — the Assuan loop owns
        // the lifecycle.
        false
    }
}

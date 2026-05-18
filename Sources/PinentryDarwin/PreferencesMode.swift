// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// PreferencesMode.swift — foreground entry for `pinentry-darwin --preferences`.
//
// Differences from daemon mode:
//   - Activation policy is `.regular` (Dock icon visible).
//   - We do NOT open an Assuan session; stdin/stdout aren't a gpg-agent pipe.
//   - We host `SettingsRootView` in a real NSWindow that the user can close
//     via Cmd-W or the red traffic light. Quitting via Cmd-Q ends the app.

import AppKit
import SwiftUI
import KeychainStore
import PinentryUI

@MainActor
enum PreferencesMode {

    /// Entry point. Builds the AppDelegate-equivalent state inline because
    /// preferences mode is short-lived and doesn't need the Assuan plumbing.
    static func run() {
        let app = NSApplication.shared
        app.setActivationPolicy(.regular)

        // NSApplication needs a delegate that survives the run loop.
        let delegate = PreferencesAppDelegate()
        app.delegate = delegate

        // Standard menu bar so the user has File/Edit/Window/Help and
        // Cmd-Q works. We populate just the application menu (with Quit)
        // and let SwiftUI's TabView contribute its own command structure
        // for the Settings tabs.
        installMinimalMainMenu()

        app.run()
    }

    // MARK: - Menu

    /// Build a minimal main menu: just the application submenu with Quit.
    /// Without this Cmd-Q is dead and the user has no way out short of
    /// killing the process.
    private static func installMinimalMainMenu() {
        let mainMenu = NSMenu()

        // Application menu: stays as the leftmost item by AppKit convention.
        let appMenuItem = NSMenuItem()
        let appMenu = NSMenu()
        appMenu.addItem(
            withTitle: "Quit pinentry-darwin",
            action: #selector(NSApplication.terminate(_:)),
            keyEquivalent: "q"
        )
        appMenuItem.submenu = appMenu
        mainMenu.addItem(appMenuItem)

        // Window menu so Cmd-W on the prefs window does the standard close.
        let windowMenuItem = NSMenuItem()
        let windowMenu = NSMenu(title: "Window")
        windowMenu.addItem(
            withTitle: "Close",
            action: #selector(NSWindow.performClose(_:)),
            keyEquivalent: "w"
        )
        windowMenuItem.submenu = windowMenu
        mainMenu.addItem(windowMenuItem)

        NSApplication.shared.mainMenu = mainMenu
    }
}

// MARK: - PreferencesAppDelegate

@MainActor
private final class PreferencesAppDelegate: NSObject, NSApplicationDelegate {

    private var window: NSWindow?
    private let uiStore = UISettingsStore()

    func applicationDidFinishLaunching(_ notification: Notification) {
        Task { @MainActor in
            let initial = await uiStore.load()
            self.openSettingsWindow(initial: initial)
        }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        // Closing the only Settings window quits the prefs app.
        true
    }

    @MainActor
    private func openSettingsWindow(initial: UISettings) {
        let store = uiStore
        let saveUI: @Sendable (UISettings) -> Void = { newValue in
            Task {
                await store.save(newValue)
            }
        }

        // Per-key Forget action — deletes the keychain entry for one
        // fingerprint. Runs off the main actor so SecItemDelete (which
        // can prompt for biometric unlock) does not block the UI run loop.
        let forget: @Sendable (String) async -> Void = { fpr in
            let keychain = KeychainStore()
            try? keychain.clear(fingerprint: fpr)
        }

        // KeychainStore does not currently expose a clearAll method; for
        // v1.0.0 we leave this nil and the SettingsRootView shows
        // "Coming soon" UI.
        let root = SettingsRootView(
            uiSettings: initial,
            keychainPrefs: UserPrefs(),
            clearAllPassphrases: nil,
            forgetPassphrase: forget,
            saveUI: saveUI
        )

        let hosting = NSHostingController(rootView: root)
        let win = NSWindow(contentViewController: hosting)
        win.title = "Pinentry Darwin Settings"
        win.styleMask = [.titled, .closable, .miniaturizable, .resizable]
        win.setContentSize(NSSize(width: 560, height: 400))
        win.center()
        win.makeKeyAndOrderFront(nil)

        NSApp.activate(ignoringOtherApps: true)
        self.window = win
    }
}

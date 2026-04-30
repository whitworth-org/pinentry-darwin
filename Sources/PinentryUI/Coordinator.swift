// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// Coordinator.swift — the bridge between the AppDelegate / Assuan
// Session and the SwiftUI view layer. The executable instantiates one
// `PinentryCoordinator` and calls `present(_:)` once per Assuan
// GETPIN/CONFIRM/MESSAGE command.

import AppKit
import SwiftUI
import KeychainStore
import SecureMemory

@MainActor
public final class PinentryCoordinator {

    private let userPrefs: UserPrefs
    private let uiSettings: UISettings

    public init(
        userPrefs: UserPrefs = UserPrefs(),
        uiSettings: UISettings = UISettings()
    ) {
        self.userPrefs = userPrefs
        self.uiSettings = uiSettings
    }

    /// Show the dialog implied by `spec` and suspend until the user (or
    /// the timeout) resolves it. Resumed exactly once.
    public func present(_ spec: DialogSpec) async -> DialogResult {
        await withCheckedContinuation { (cont: CheckedContinuation<DialogResult, Never>) in
            self.show(spec: spec, continuation: cont)
        }
    }

    // MARK: - Internals

    /// One-shot resolver: forwards the first incoming result and ignores
    /// the rest. We share a single `Resolver` between the view-model
    /// callback, the close-button handler, and the timeout timer so any
    /// of the three paths can win.
    @MainActor
    private final class Resolver {
        private var continuation: CheckedContinuation<DialogResult, Never>?
        // Strong reference: NSApp keeps visible windows alive while
        // ordered-in, but holding our own ref until resolution is
        // defensive against early dealloc.
        var window: NSWindow?
        /// Timeout source. Timer is RunLoop-driven so it fires reliably
        /// from inside `NSApp.runModal`'s event loop; a Task with
        /// `Task.sleep` would compete with the modal's main-actor
        /// hold and could delay or fail to fire.
        var timeoutTimer: Timer?

        init(_ continuation: CheckedContinuation<DialogResult, Never>) {
            self.continuation = continuation
        }

        func resolve(_ result: DialogResult) {
            guard let cont = continuation else { return }
            continuation = nil
            timeoutTimer?.invalidate()
            timeoutTimer = nil
            cont.resume(returning: result)
            // End the modal session BEFORE closing the window so the
            // run-loop returns from `runModal(for:)` cleanly. Closing
            // the window first works (close → abortModal under the
            // hood) but the explicit stopModal makes the contract
            // unambiguous and survives any future close-handling
            // refactor.
            NSApp.stopModal()
            // Mark dismissal as resolver-driven before closing so
            // PinentryWindow.close() doesn't re-fire onCloseRequested.
            if let pw = window as? PinentryWindow {
                pw.isResolvingDismissal = true
            }
            window?.close()
            window = nil
            // Defensive: if SwiftUI's onDisappear didn't fire (rare under
            // window-close-from-resolve paths), zero out any outstanding
            // SKE enables so the menu-bar lock doesn't stick around.
            // This is a no-op when the view's onDisappear already
            // balanced its own enable.
            SecureInput.reset()
        }
    }

    private func show(
        spec: DialogSpec,
        continuation: CheckedContinuation<DialogResult, Never>
    ) {
        let resolver = Resolver(continuation)

        let window: NSWindow
        switch spec.kind {
        case .pin:
            let model = PinViewModel(
                spec: spec,
                showTypingByDefault: userPrefs.showTypingByDefault,
                saveByDefault: userPrefs.saveByDefault,
                onResult: { [resolver] result in
                    // PinViewModel is @MainActor-isolated, so this closure
                    // is called on the main actor; resolve directly.
                    resolver.resolve(result)
                }
            )
            let root = applyTheme(PinView(
                spec: spec,
                model: model,
                secureKeyboardEntry: uiSettings.secureKeyboardEntry
            ))
            window = makePinentryWindow(rootView: root, title: spec.title)

        case .confirm:
            let root = applyTheme(ConfirmView(spec: spec) { [resolver] result in
                resolver.resolve(result)
            })
            window = makePinentryWindow(rootView: root, title: spec.title)

        case .message:
            let root = applyTheme(MessageView(spec: spec) { [resolver] result in
                resolver.resolve(result)
            })
            window = makePinentryWindow(rootView: root, title: spec.title)
        }

        // Tell the window what to do on red-button close.
        if let pw = window as? PinentryWindow {
            pw.onCloseRequested = { [resolver] in
                resolver.resolve(.windowClosed)
            }
        }
        resolver.window = window

        // Position + present. Centre, then bring forward.
        window.center()
        NSApp.activate(ignoringOtherApps: true)

        // Apply timeout if requested. SETTIMEOUT 0 means "no timeout".
        // Timer (not Task.sleep) so the source is RunLoop-pumped under
        // NSApp.runModal — the modal session does not reliably yield
        // the main-actor scheduler that backs Task.sleep, so a Task
        // would risk firing late or not at all.
        if let seconds = spec.timeoutSeconds, seconds > 0 {
            let timer = Timer.scheduledTimer(
                withTimeInterval: TimeInterval(seconds),
                repeats: false
            ) { [resolver] _ in
                MainActor.assumeIsolated {
                    resolver.resolve(.timedOut)
                }
            }
            resolver.timeoutTimer = timer
        }

        // Drive a true app-modal session. Compared to the previous
        // `makeKeyAndOrderFront` + `.floating` posture, this:
        //   * disables event delivery to other windows belonging to
        //     this process (no-op for pinentry-darwin since we own
        //     exactly one window — but the contract is explicit);
        //   * presents to AT/AX as a modal rather than a floating
        //     auxiliary, which is the correct semantic for a
        //     passphrase prompt;
        //   * blocks here until `Resolver.resolve` calls
        //     `NSApp.stopModal()` (or the user closes the window,
        //     which `abortModal`s automatically).
        // SwiftUI button handlers and our Timer both fire from the
        // main run loop while runModal is pumping, which is what
        // delivers the result that ends the session.
        NSApp.runModal(for: window)
    }

    /// Apply the theme override (if any). System mode never sets
    /// `.preferredColorScheme` so the window inherits live changes from
    /// `NSApp.effectiveAppearance`.
    @ViewBuilder
    private func applyTheme<V: View>(_ root: V) -> some View {
        switch uiSettings.theme {
        case .system:
            root
        case .light:
            root.preferredColorScheme(.light)
        case .dark:
            root.preferredColorScheme(.dark)
        }
    }
}

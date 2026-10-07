// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// PinentryUIPrefs.swift — UI-only settings (theme override, default
// timeout, input hardening toggles) persisted to our own UserDefaults suite
// `org.whitworth.pinentry-darwin` under the key `UISettings` as a JSON
// blob. Keychain-related toggles live in `KeychainStore.UserPrefs`.
//
// The Settings views accept both `UISettings` and `KeychainStore.UserPrefs`.
// Keeping them split avoids name collisions across modules and lets each
// store own its persistence.

public import Foundation

// MARK: - UISettings

public struct UISettings: Sendable, Codable, Equatable {

    public enum Theme: String, CaseIterable, Sendable, Codable {
        case system, light, dark
    }

    public var theme: Theme = .system
    /// Seconds before a dialog gives up when gpg-agent sent no SETTIMEOUT.
    /// 0 disables the fallback. Range 0…600 in the UI.
    public var defaultTimeout: Int = 0
    /// When the user paste-fills the passphrase field, wipe
    /// `NSPasteboard.general` on submit so the cleartext doesn't
    /// linger in the system clipboard. Detected via change-count
    /// delta — we never inspect pasteboard contents. Default ON.
    public var clearPasteboardOnSubmit: Bool = true

    public init(
        theme: Theme = .system,
        defaultTimeout: Int = 0,
        clearPasteboardOnSubmit: Bool = true
    ) {
        self.theme = theme
        self.defaultTimeout = defaultTimeout
        self.clearPasteboardOnSubmit = clearPasteboardOnSubmit
    }
}

// MARK: - UISettingsStore

/// Actor-isolated read/write of the `UISettings` blob. We use an actor (not
/// raw UserDefaults methods on the call site) so concurrent reads from
/// presentation paths and writes from Settings views are serialised.
public actor UISettingsStore {

    // Suite name kept distinct from the bundle identifier so we don't trip
    // the `_NSUserDefaults_Log_Nonsensical_Suites` warning. NSUserDefaults
    // refuses to use the running app's bundle id as a suite (it would
    // collide with the standard domain).
    public static let suiteName = "org.whitworth.pinentry-darwin.prefs"
    public static let key = "UISettings"

    private let defaults: UserDefaults

    public init(defaults: UserDefaults? = nil) {
        if let defaults {
            self.defaults = defaults
        } else if let suite = UserDefaults(suiteName: UISettingsStore.suiteName) {
            self.defaults = suite
        } else {
            self.defaults = .standard
        }
    }

    public func load() -> UISettings {
        guard let data = defaults.data(forKey: UISettingsStore.key) else {
            return UISettings()
        }
        do {
            return try JSONDecoder().decode(UISettings.self, from: data)
        } catch {
            // Corrupt blob — return defaults rather than crash. We deliberately
            // do NOT log the error: it might contain user-supplied values.
            return UISettings()
        }
    }

    public func save(_ settings: UISettings) {
        do {
            let data = try JSONEncoder().encode(settings)
            defaults.set(data, forKey: UISettingsStore.key)
        } catch {
            // Encoding a fixed Codable struct cannot realistically fail;
            // swallow the error to avoid leaking values into a logger.
        }
    }
}

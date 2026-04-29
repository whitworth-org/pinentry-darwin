// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// UserPrefs: read keychain-related preferences from our own UserDefaults
// suite, falling back to org.gpgtools.common keys so existing pinentry-mac
// users carry their preferences forward on first launch.
//
// Resolution rules (writes always go to our own suite):
//   keychainEnabled:    own KeychainEnabled (Bool)
//                       else gpgtools DisableKeychain == true → false
//                       else gpgtools UseKeychain == false   → false
//                       else true.
//   saveByDefault:      own SaveByDefault, else true.
//   showTypingByDefault: own ShowTyping,
//                       else gpgtools ShowPassphrase,
//                       else false.

import Foundation
import Security
import SecureMemory

// MARK: - Keys

/// Keys used in our own UserDefaults suite.
private enum OwnKey {
    static let keychainEnabled     = "KeychainEnabled"
    static let saveByDefault       = "SaveByDefault"
    static let showTyping          = "ShowTyping"
}

/// Keys used in org.gpgtools.common (read-only, for pinentry-mac compat).
private enum GPGToolsKey {
    static let useKeychain     = "UseKeychain"
    static let disableKeychain = "DisableKeychain"
    static let showPassphrase  = "ShowPassphrase"
}

// MARK: - UserPrefs

// `UserDefaults` is documented thread-safe but not formally `Sendable`.
// We retain it as a `let` and only call documented-safe APIs, so `@unchecked
// Sendable` is the pragmatic escape hatch here.
public struct UserPrefs: @unchecked Sendable {

    /// Our own preference store. Tests typically pass an ephemeral suite.
    private let defaults: UserDefaults

    /// Optional fallback store. nil disables the gpgtools-compat reads
    /// entirely (handy for tests that need a clean slate).
    private let gpgToolsDefaults: UserDefaults?

    public init(
        defaults: UserDefaults = .standard,
        gpgToolsDefaults: UserDefaults? = UserDefaults(suiteName: "org.gpgtools.common")
    ) {
        self.defaults = defaults
        self.gpgToolsDefaults = gpgToolsDefaults
    }

    // MARK: Reads

    public var keychainEnabled: Bool {
        if defaults.object(forKey: OwnKey.keychainEnabled) != nil {
            return defaults.bool(forKey: OwnKey.keychainEnabled)
        }
        if let gp = gpgToolsDefaults {
            if gp.object(forKey: GPGToolsKey.disableKeychain) != nil,
               gp.bool(forKey: GPGToolsKey.disableKeychain) {
                return false
            }
            if gp.object(forKey: GPGToolsKey.useKeychain) != nil,
               gp.bool(forKey: GPGToolsKey.useKeychain) == false {
                return false
            }
        }
        return true
    }

    public var saveByDefault: Bool {
        if defaults.object(forKey: OwnKey.saveByDefault) != nil {
            return defaults.bool(forKey: OwnKey.saveByDefault)
        }
        return true
    }

    public var showTypingByDefault: Bool {
        if defaults.object(forKey: OwnKey.showTyping) != nil {
            return defaults.bool(forKey: OwnKey.showTyping)
        }
        if let gp = gpgToolsDefaults,
           gp.object(forKey: GPGToolsKey.showPassphrase) != nil {
            return gp.bool(forKey: GPGToolsKey.showPassphrase)
        }
        return false
    }

    // MARK: Writes

    public mutating func set(keychainEnabled value: Bool) {
        defaults.set(value, forKey: OwnKey.keychainEnabled)
    }

    public mutating func set(saveByDefault value: Bool) {
        defaults.set(value, forKey: OwnKey.saveByDefault)
    }

    public mutating func set(showTypingByDefault value: Bool) {
        defaults.set(value, forKey: OwnKey.showTyping)
    }
}

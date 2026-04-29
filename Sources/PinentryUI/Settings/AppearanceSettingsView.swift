// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// AppearanceSettingsView.swift — Settings → Appearance tab.
//
// IMPORTANT: the theme override is applied at present-time (via
// `Coordinator.applyTheme`) only when the user picks a non-system value.
// We never call `.preferredColorScheme()` on a view whose theme is
// `.system`; that would short-circuit live `NSApp.effectiveAppearance`.

import SwiftUI
import KeychainStore

public struct AppearanceSettingsView: View {
    @Binding public var settings: UISettings
    @Binding public var keychainPrefs: UserPrefs
    public var onChange: (UISettings) -> Void

    public init(
        settings: Binding<UISettings>,
        keychainPrefs: Binding<UserPrefs>,
        onChange: @escaping (UISettings) -> Void
    ) {
        self._settings = settings
        self._keychainPrefs = keychainPrefs
        self.onChange = onChange
    }

    public var body: some View {
        Form {
            Section("Theme") {
                Picker("Appearance", selection: $settings.theme) {
                    Text("System").tag(UISettings.Theme.system)
                    Text("Light").tag(UISettings.Theme.light)
                    Text("Dark").tag(UISettings.Theme.dark)
                }
                .pickerStyle(.segmented)
                .onChange(of: settings.theme) { _, _ in onChange(settings) }
            }

            Section("Window") {
                Picker("Titlebar style", selection: $settings.titlebarStyle) {
                    Text("Transparent").tag(UISettings.TitlebarStyle.transparent)
                    Text("Hidden").tag(UISettings.TitlebarStyle.hidden)
                    Text("Standard").tag(UISettings.TitlebarStyle.standard)
                }
                .onChange(of: settings.titlebarStyle) { _, _ in onChange(settings) }
            }

            Section("Input") {
                Toggle("Show typing by default", isOn: Binding(
                    get: { keychainPrefs.showTypingByDefault },
                    set: { newValue in
                        // Mutate via the binding's wrappedValue so the
                        // struct's `mutating` setter sees a writable self.
                        // The struct embeds a UserDefaults class ref, so
                        // the persisted side effect lands in either case;
                        // routing through $keychainPrefs also republishes
                        // the in-memory value to SwiftUI observers.
                        var copy = keychainPrefs
                        copy.set(showTypingByDefault: newValue)
                        keychainPrefs = copy
                    }
                ))
            }

            Text("Theme changes apply to the next dialog.")
                .font(Theme.captionFont)
                .foregroundStyle(Color.secondary)
        }
        .padding(Theme.mediumPadding)
    }
}

// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// SettingsToolbar.swift — the tab model for the Settings window and the
// native preference-style toolbar (icon over label, centred in the title
// bar) that switches between tabs. SwiftUI's TabView draws the old
// bordered tab control when hosted in an NSWindow, so the window gets a
// real NSToolbar instead.

import AppKit
import SwiftUI

enum SettingsTab: String, CaseIterable, Identifiable {
    case appearance
    case behaviour
    case keychain
    case perKey
    case ssh
    case about

    var id: String { rawValue }

    var title: String {
        switch self {
        case .appearance: "Appearance"
        case .behaviour: "Behaviour"
        case .keychain: "Keychain"
        case .perKey: "Per-key policy"
        case .ssh: "SSH"
        case .about: "About"
        }
    }

    var symbol: String {
        switch self {
        case .appearance: "paintbrush"
        case .behaviour: "slider.horizontal.3"
        case .keychain: "lock.rectangle.stack"
        case .perKey: "key"
        case .ssh: "terminal"
        case .about: "info.circle"
        }
    }

    fileprivate var itemIdentifier: NSToolbarItem.Identifier { .init(rawValue) }
}

/// Installs a preference-style `NSToolbar` on the hosting window and keeps
/// it in sync with `selection`.
struct SettingsToolbarInstaller: NSViewRepresentable {

    @Binding var selection: SettingsTab

    func makeCoordinator() -> SettingsToolbarController {
        SettingsToolbarController(selection: $selection)
    }

    func makeNSView(context: Context) -> NSView {
        let view = WindowObservingView()
        view.onWindow = { [weak controller = context.coordinator] window in
            controller?.install(on: window)
        }
        return view
    }

    func updateNSView(_ nsView: NSView, context: Context) {
        context.coordinator.selection = $selection
        context.coordinator.syncSelection()
    }
}

private final class WindowObservingView: NSView {
    var onWindow: ((NSWindow) -> Void)?

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        if let window = unsafe window { onWindow?(window) }
    }
}

@MainActor
final class SettingsToolbarController: NSObject, NSToolbarDelegate {

    var selection: Binding<SettingsTab>
    private(set) var toolbar: NSToolbar?
    private weak var window: NSWindow?

    init(selection: Binding<SettingsTab>) {
        self.selection = selection
    }

    func install(on window: NSWindow) {
        guard toolbar == nil else { return }
        let toolbar = NSToolbar(identifier: "SettingsToolbar")
        toolbar.delegate = self
        toolbar.displayMode = .iconAndLabel
        toolbar.allowsUserCustomization = false
        window.toolbarStyle = .preference
        window.toolbar = toolbar
        self.toolbar = toolbar
        self.window = window
        syncSelection()
        // The executable names the window right after creating it; apply the
        // pane title again once that code has run.
        Task { @MainActor [weak self] in self?.syncSelection() }
    }

    func syncSelection() {
        toolbar?.selectedItemIdentifier = selection.wrappedValue.itemIdentifier
        window?.title = selection.wrappedValue.title
    }

    @objc func itemClicked(_ sender: NSToolbarItem) {
        guard let tab = SettingsTab(rawValue: sender.itemIdentifier.rawValue) else { return }
        selection.wrappedValue = tab
    }

    // MARK: NSToolbarDelegate

    func toolbarAllowedItemIdentifiers(_ toolbar: NSToolbar) -> [NSToolbarItem.Identifier] {
        SettingsTab.allCases.map(\.itemIdentifier)
    }

    func toolbarDefaultItemIdentifiers(_ toolbar: NSToolbar) -> [NSToolbarItem.Identifier] {
        SettingsTab.allCases.map(\.itemIdentifier)
    }

    func toolbarSelectableItemIdentifiers(_ toolbar: NSToolbar) -> [NSToolbarItem.Identifier] {
        SettingsTab.allCases.map(\.itemIdentifier)
    }

    func toolbar(
        _ toolbar: NSToolbar,
        itemForItemIdentifier itemIdentifier: NSToolbarItem.Identifier,
        willBeInsertedIntoToolbar flag: Bool
    ) -> NSToolbarItem? {
        guard let tab = SettingsTab(rawValue: itemIdentifier.rawValue) else { return nil }
        let item = NSToolbarItem(itemIdentifier: itemIdentifier)
        item.label = tab.title
        item.paletteLabel = tab.title
        item.toolTip = tab.title
        item.image = NSImage(systemSymbolName: tab.symbol, accessibilityDescription: tab.title)
        item.target = self
        item.action = #selector(itemClicked(_:))
        return item
    }
}

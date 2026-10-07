// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// DialogHeader.swift — the layout shared by the GETPIN, CONFIRM and MESSAGE
// dialogs: icon on the left; title, description and key info on the right;
// a status line primitive; and the button row.
//
// Every spec.* string comes from gpg-agent SET* lines and is rendered with
// Text(verbatim:) so it can never be interpreted as markdown or a link.

import SwiftUI

// MARK: - Local tokens

/// Constants that Theme does not provide. Kept here so Theme stays untouched.
enum DialogStyle {
    /// SETTITLE heading. A relative system style so it follows text-size changes.
    static let titleFont: Font = .title2.weight(.semibold)

    /// Height beyond which SETDESC scrolls. Keeps the buttons on screen however
    /// much text gpg-agent sends, while still showing every line on demand.
    static let maxDescriptionHeight: CGFloat = 220

    /// Fade duration for status-line changes.
    static let statusFadeDuration: Double = 0.15
}

extension Optional where Wrapped == String {
    /// The wrapped string, or nil when it is nil or empty.
    var nonEmpty: String? {
        guard let self, !self.isEmpty else { return nil }
        return self
    }
}

// MARK: - Scaffold

/// Icon column plus content column, with the dialog's outer padding and a
/// fade-in that is skipped under Reduce Motion.
struct DialogScaffold<Content: View, Footer: View>: View {
    let symbol: String
    let content: Content
    let footer: Footer

    @ScaledMetric(relativeTo: .title) private var iconSize = Theme.heroIconSize

    init(
        symbol: String,
        @ViewBuilder content: () -> Content,
        @ViewBuilder footer: () -> Footer
    ) {
        self.symbol = symbol
        self.content = content()
        self.footer = footer()
    }

    var body: some View {
        HStack(alignment: .top, spacing: Theme.blockPadding) {
            Image(systemName: symbol)
                .font(.system(size: iconSize))
                .foregroundStyle(Theme.accent)
                .frame(width: iconSize + 8, alignment: .top)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: Theme.mediumPadding) {
                content
                footer.padding(.top, Theme.smallPadding)
            }
        }
        .padding(.horizontal, Theme.largePadding)
        .padding(.vertical, Theme.blockPadding)
        .frame(maxWidth: .infinity, alignment: .leading)
        .modifier(FadeInOnAppear())
    }
}

/// Opacity-only entrance. No offset, so the field is never displaced while it
/// takes focus; no animation at all when Reduce Motion is on.
private struct FadeInOnAppear: ViewModifier {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var appeared = false

    func body(content: Content) -> some View {
        content
            .opacity(appeared || reduceMotion ? 1 : 0)
            .onAppear {
                withAnimation(reduceMotion ? nil : .easeOut(duration: Theme.entranceDuration)) {
                    appeared = true
                }
            }
    }
}

// MARK: - Text block

/// Title, description and key info. Used identically by all three dialogs.
struct DialogTextBlock: View {
    let spec: DialogSpec

    var body: some View {
        VStack(alignment: .leading, spacing: Theme.smallPadding) {
            if let title = spec.title.nonEmpty {
                Text(verbatim: title)
                    .font(DialogStyle.titleFont)
                    .lineLimit(4)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityAddTraits(.isHeader)
            }
            if let description = spec.description.nonEmpty {
                ScrollingDescription(text: description)
            }
            if case let .key(mode, fingerprint) = spec.keyInfo {
                KeyInfoText(mode: mode, fingerprint: fingerprint)
            }
        }
    }
}

/// SETDESC: selectable, wraps, and scrolls once it passes the height cap.
private struct ScrollingDescription: View {
    let text: String

    var body: some View {
        ScrollView(.vertical) {
            Text(verbatim: text)
                .font(Theme.bodyFont)
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .fixedSize(horizontal: false, vertical: true)
        }
        .scrollBounceBehavior(.basedOnSize)
        .frame(maxHeight: DialogStyle.maxDescriptionHeight)
        .fixedSize(horizontal: false, vertical: true)
    }
}

/// SETKEYINFO, monospaced and selectable so it can be compared digit by digit.
private struct KeyInfoText: View {
    let mode: Character
    let fingerprint: String

    var body: some View {
        let label = KeyInfoFormat.label(mode: mode, fingerprint: fingerprint)
        VStack(alignment: .leading, spacing: 2) {
            if let caption = label.caption {
                Text(verbatim: caption)
                    .font(Theme.captionFont)
                    .foregroundStyle(.secondary)
            }
            Text(verbatim: label.value)
                .font(Theme.monospacedFont)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
                .speechSpellsOutCharacters()
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel(Text(verbatim: label.spoken))
    }
}

/// Pure formatting of SETKEYINFO so it can be tested without a view.
enum KeyInfoFormat {
    struct Label: Equatable {
        /// Short secondary line naming the kind of key, when it is not the default.
        let caption: String?
        /// The fingerprint, grouped for comparison.
        let value: String
        /// Text VoiceOver reads for the whole element.
        let spoken: String
    }

    static func label(mode: Character, fingerprint: String) -> Label {
        let value = grouped(fingerprint)
        let caption: String? =
            switch mode {
            case "c": "Card key"
            case "s": "SSH key"
            default: nil
            }
        let spoken = "\(caption ?? "Key") \(value)"
        return Label(caption: caption, value: value, spoken: spoken)
    }

    /// 40 hex digits become two groups of five quads, as `gpg --fingerprint`
    /// prints them. Any other string is shown as given.
    static func grouped(_ fingerprint: String) -> String {
        let hex = fingerprint.uppercased()
        guard hex.count == 40, hex.allSatisfy(\.isHexDigit) else { return fingerprint }
        let quads = stride(from: 0, to: 40, by: 4).map { start -> String in
            let low = hex.index(hex.startIndex, offsetBy: start)
            return String(hex[low..<hex.index(low, offsetBy: 4)])
        }
        let halves = [quads.prefix(5), quads.suffix(5)]
        return halves.map { $0.joined(separator: " ") }.joined(separator: "  ")
    }
}

// MARK: - Status line

/// One line of feedback: a shape-coded icon plus primary-coloured text, so the
/// message is legible without relying on red text (about 3.5:1 on white).
struct StatusLine: View {
    enum Tone: Equatable {
        case error, success, info

        var symbol: String {
            switch self {
            case .error: "exclamationmark.triangle.fill"
            case .success: "checkmark.circle.fill"
            case .info: "info.circle.fill"
            }
        }

        var tint: Color {
            switch self {
            case .error: Theme.errorText
            case .success: Theme.success
            case .info: Color.secondary
            }
        }
    }

    let tone: Tone
    let text: String

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: Theme.smallPadding - 2) {
            Image(systemName: tone.symbol)
                .foregroundStyle(tone.tint)
                .accessibilityHidden(true)
            Text(verbatim: text)
                .foregroundStyle(tone == .info ? .secondary : .primary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .font(.callout)
        .accessibilityElement(children: .combine)
    }
}

// MARK: - Buttons

enum DialogButtonRole: Hashable {
    case notOK, cancel, ok

    /// Left-to-right order: the negative alternative, Cancel, then the
    /// default action on the right, as in a macOS alert.
    static func layout(oneButton: Bool, notOKLabel: String?) -> [DialogButtonRole] {
        if oneButton { return [.ok] }
        return (notOKLabel.nonEmpty == nil ? [] : [.notOK]) + [.cancel, .ok]
    }

    /// The Assuan result a CONFIRM dialog reports when this button is pressed.
    var confirmResult: DialogResult {
        switch self {
        case .ok: .confirmed
        case .notOK: .notConfirmed
        case .cancel: .canceled
        }
    }
}

/// Right-aligned button row. OK is the default (Return); Cancel answers Escape.
struct DialogButtonRow: View {
    let spec: DialogSpec
    let oneButton: Bool
    var okEnabled = true
    var isBusy = false
    let onAction: (DialogButtonRole) -> Void

    var body: some View {
        HStack(spacing: Theme.smallPadding) {
            Spacer(minLength: 0)
            ForEach(
                DialogButtonRole.layout(oneButton: oneButton, notOKLabel: spec.notOKLabel),
                id: \.self
            ) { role in
                button(for: role)
            }
        }
    }

    @ViewBuilder
    private func button(for role: DialogButtonRole) -> some View {
        switch role {
        case .notOK:
            Button(spec.notOKLabel ?? "") { onAction(.notOK) }
        case .cancel:
            Button(spec.resolvedCancel) { onAction(.cancel) }
                .keyboardShortcut(.cancelAction)
        case .ok:
            Button { onAction(.ok) } label: { okLabel }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(PrimaryButtonStyle())
                .disabled(!okEnabled || isBusy)
        }
    }

    @ViewBuilder
    private var okLabel: some View {
        if isBusy {
            HStack(spacing: 6) {
                ProgressView().controlSize(.small)
                Text(verbatim: spec.resolvedOK)
            }
        } else {
            Text(verbatim: spec.resolvedOK)
        }
    }
}

// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// Mnemonic.swift — strip GTK accelerator markers from button/option labels.
//
// gpg-agent ships labels with GTK underscore mnemonics (e.g. "_OK" means
// label "OK" with Alt-O as the keyboard accelerator). On macOS, accelerator
// markers don't apply, so the underscore would render as literal text.
// Apply this at the wire-to-spec boundary so DialogSpec carries clean
// strings and the Views stay dumb renderers.
//
// Convention (per GTK GtkLabel docs):
//   _X   → X     single underscore is the mnemonic marker
//   __   → _     two underscores escape one literal underscore
//   foo_ → foo   trailing dangling underscore is dropped (malformed)

import Foundation

public enum Mnemonic {

    /// Unicode codepoints whose visual effect can re-order or hide
    /// adjacent text — they have no place in a button label or prompt
    /// and any presence is treated as attacker-supplied (FV-6).
    /// Categories:
    ///   U+200B-U+200F  zero-width / formatting / LRM/RLM
    ///   U+202A-U+202E  legacy bidi overrides (LRE/RLE/PDF/LRO/RLO)
    ///   U+2060-U+2069  word-joiner + bidi isolates
    ///   U+FEFF         BOM / zero-width no-break space
    @inline(__always)
    private static func isBidiOrInvisible(_ scalar: Unicode.Scalar) -> Bool {
        let v = scalar.value
        return (0x200B...0x200F).contains(v)
            || (0x202A...0x202E).contains(v)
            || (0x2060...0x2069).contains(v)
            || v == 0xFEFF
    }

    /// Strip GTK underscore accelerator markers from `s` and reject
    /// embedded bidi-override / invisible codepoints (FV-6).
    public static func strip(_ s: String) -> String {
        var result = ""
        result.reserveCapacity(s.count)
        var i = s.startIndex
        while i < s.endIndex {
            let c = s[i]
            if c == "_" {
                let next = s.index(after: i)
                if next < s.endIndex {
                    if s[next] == "_" {
                        result.append("_")
                        i = s.index(after: next)
                        continue
                    }
                    i = next
                    continue
                }
                break
            }
            // FV-6: drop any character whose scalar set includes a
            // bidi-override / zero-width / BOM codepoint. We drop the
            // entire grapheme rather than try to surgically excise the
            // offending scalar — a "u + RLO" cluster is not legible
            // either way, and the safe action is to omit it.
            if c.unicodeScalars.contains(where: Self.isBidiOrInvisible) {
                i = s.index(after: i)
                continue
            }
            result.append(c)
            i = s.index(after: i)
        }
        return result
    }

    /// Convenience for optional labels — nil flows through. Named distinctly
    /// from `strip(_:)` because Swift overload resolution can't disambiguate
    /// `String` vs `String?` at call sites where the result is assigned to
    /// an optional.
    public static func stripOptional(_ s: String?) -> String? {
        s.map(strip)
    }

    /// FV-6 filter for non-mnemonic body text. Drops grapheme clusters that
    /// contain any bidi-override / zero-width / BOM codepoint. No GTK
    /// underscore handling, so `_` survives — apply this to SETDESC /
    /// SETTITLE / SETERROR / SETREPEATERROR payloads where an underscore is
    /// part of the message, not an accelerator marker.
    public static func sanitiseBody(_ s: String) -> String {
        var result = ""
        result.reserveCapacity(s.count)
        for c in s where !c.unicodeScalars.contains(where: Self.isBidiOrInvisible) {
            result.append(c)
        }
        return result
    }

    /// Optional-friendly variant of `sanitiseBody`. Mirrors `stripOptional`
    /// so AssuanLoop / OptionState call sites that hold String? values
    /// don't have to unwrap before sanitising.
    public static func sanitiseBodyOptional(_ s: String?) -> String? {
        s.map(sanitiseBody)
    }
}

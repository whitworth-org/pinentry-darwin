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

    /// Strip GTK underscore accelerator markers from `s`.
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
}

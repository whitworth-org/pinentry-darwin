#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright 2026 Ryan Whitworth.
#
# audit-bundle.sh — static-audit the built pinentry-darwin.app bundle.
#
# Verifies, without launching the binary or hitting the network:
#   - Mach-O present, arm64, executable bit set
#   - Linked dylibs are exclusively /usr/lib/* and /System/Library/Frameworks/*
#     (catches accidental /opt/homebrew or /usr/local third-party links)
#   - Bundle structure: Info.plist, MacOS/<bin>, entitlements file
#   - Info.plist invariants: bundle id, LSUIElement=true, version present
#   - Entitlements: hardened runtime allow-jit/allow-unsigned-executable-memory
#     intentionally absent (we want real hardening); app-sandbox absent
#     (sandbox breaks gpg-agent stdio inheritance)
#   - Codesign: present (ad-hoc OK for dev builds; Developer ID required for
#     `--release` mode)
#
# Usage:
#   scripts/audit-bundle.sh              # default bundle path
#   scripts/audit-bundle.sh path/to/app  # explicit path
#   scripts/audit-bundle.sh --release    # additionally require Developer ID
#                                          codesign + stapled notarization
#
# Exits 0 if all checks pass, 1 otherwise (with offending findings on stderr).

set -euo pipefail

RELEASE_MODE=0
APP_BUNDLE="${1:-build/pinentry-darwin.app}"
if [ "${1:-}" = "--release" ]; then
    RELEASE_MODE=1
    APP_BUNDLE="${2:-build/pinentry-darwin.app}"
fi

if [ ! -d "$APP_BUNDLE" ]; then
    echo "audit: bundle not found at $APP_BUNDLE" >&2
    exit 2
fi

BIN="$APP_BUNDLE/Contents/MacOS/pinentry-darwin"
INFO_PLIST="$APP_BUNDLE/Contents/Info.plist"

# Repo-relative source-of-truth for entitlements. Used as a fallback when the
# binary isn't signed yet. After `make sign`, audit reads the embedded
# entitlements from the signature itself (codesign -d --entitlements -).
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENTITLEMENTS_SRC="$REPO_ROOT/App/pinentry-darwin.entitlements"

fails=0
fail() {
    echo "audit: FAIL — $1" >&2
    fails=$((fails+1))
}

# --- Bundle structure --------------------------------------------------------

[ -x "$BIN" ]            || fail "missing executable: $BIN"
[ -f "$INFO_PLIST" ]     || fail "missing Info.plist"
[ -f "$ENTITLEMENTS_SRC" ] || fail "missing source entitlements: $ENTITLEMENTS_SRC"

# --- Mach-O shape ------------------------------------------------------------

if [ -x "$BIN" ]; then
    arch_line="$(file "$BIN" | head -n1)"
    case "$arch_line" in
        *"Mach-O 64-bit executable arm64"*) ;;
        *) fail "expected arm64 Mach-O, got: $arch_line" ;;
    esac

    # All linked libraries must come from system locations; anything in
    # /opt/homebrew, /usr/local, or @rpath would indicate a third-party leak.
    while IFS= read -r dep; do
        case "$dep" in
            /usr/lib/*|/System/Library/*) ;;
            *)  fail "non-system dylib linked: $dep" ;;
        esac
    done < <(otool -L "$BIN" | awk 'NR>1 {print $1}')
fi

# --- Info.plist invariants ---------------------------------------------------

if [ -f "$INFO_PLIST" ]; then
    bundle_id="$(plutil -extract CFBundleIdentifier raw -- "$INFO_PLIST" 2>/dev/null || true)"
    [ "$bundle_id" = "org.whitworth.pinentry-darwin" ] \
        || fail "bundle id mismatch: '$bundle_id' (want org.whitworth.pinentry-darwin)"

    short_ver="$(plutil -extract CFBundleShortVersionString raw -- "$INFO_PLIST" 2>/dev/null || true)"
    [ -n "$short_ver" ] \
        || fail "CFBundleShortVersionString missing"

    ls_ui="$(plutil -extract LSUIElement raw -- "$INFO_PLIST" 2>/dev/null || true)"
    case "$ls_ui" in
        true|1|YES) ;;
        *) fail "LSUIElement must be true (no Dock icon for Assuan agent mode); got '$ls_ui'" ;;
    esac

    min_os="$(plutil -extract LSMinimumSystemVersion raw -- "$INFO_PLIST" 2>/dev/null || true)"
    case "$min_os" in
        15.*|16.*|17.*) ;;
        '') ;;  # optional; LSMinimumSystemVersion is nice-to-have
        *) fail "LSMinimumSystemVersion '$min_os' is below macOS 15 (CLAUDE.md requires 15+)" ;;
    esac
fi

# --- Entitlements ------------------------------------------------------------

# Prefer the entitlements actually embedded in the signed binary. If the
# bundle is unsigned (no embedded entitlements yet), fall back to the source
# file in App/. The set of forbidden keys is the same either way.
ENT_TMP="$(mktemp -t pd-ent.XXXXXX)"
trap 'rm -f "$ENT_TMP"' EXIT
if codesign -d --entitlements - --xml "$APP_BUNDLE" >"$ENT_TMP" 2>/dev/null && [ -s "$ENT_TMP" ]; then
    ENT_FILE="$ENT_TMP"
elif [ -f "$ENTITLEMENTS_SRC" ]; then
    ENT_FILE="$ENTITLEMENTS_SRC"
else
    ENT_FILE=""
fi

if [ -n "$ENT_FILE" ]; then
    # The app-sandbox entitlement MUST be absent — it breaks stdio inheritance
    # from gpg-agent, which is the entire point of pinentry-darwin.
    if plutil -extract com.apple.security.app-sandbox raw -- "$ENT_FILE" 2>/dev/null | grep -qE '^(true|YES|1)$'; then
        fail "app-sandbox entitlement present — must be absent (breaks gpg-agent stdio)"
    fi

    # The hardened-runtime weakening flags MUST be absent; if they're set
    # we lose the security promise of the hardened runtime.
    for weak in com.apple.security.cs.allow-jit \
                com.apple.security.cs.allow-unsigned-executable-memory \
                com.apple.security.cs.disable-library-validation; do
        if plutil -extract "$weak" raw -- "$ENT_FILE" 2>/dev/null | grep -qE '^(true|YES|1)$'; then
            fail "weakening entitlement set: $weak"
        fi
    done
fi

# --- Codesign ----------------------------------------------------------------

if [ -x "$BIN" ]; then
    if ! codesign -dv "$APP_BUNDLE" >/dev/null 2>&1; then
        fail "codesign verification failed (no signature)"
    else
        # Use --verbose=2 so Authority= lines are emitted. Plain `codesign -dv`
        # is too terse and omits the chain we need to inspect.
        cs_dump="$(codesign -dv --verbose=2 "$APP_BUNDLE" 2>&1)"
        cs_flags="$(echo "$cs_dump" | awk -F= '/^CodeDirectory v=/ {print $0}' | sed -E 's/.*flags=([^ ]*).*/\1/')"

        # Hardened runtime check: notarization requires the runtime flag to be
        # set on every Mach-O in the bundle. We check the top-level dump; the
        # flags string contains "runtime" when --options runtime was used.
        case "$cs_flags" in
            *runtime*)  ;;
            *)
                # Ad-hoc/linker-signed dev builds don't carry runtime; only fail
                # in --release mode. Default mode allows unsigned/adhoc.
                if [ "$RELEASE_MODE" -eq 1 ]; then
                    fail "hardened runtime not set (codesign flags: $cs_flags)"
                fi
                ;;
        esac

        if [ "$RELEASE_MODE" -eq 1 ]; then
            # The leaf Authority for a Developer ID-signed bundle is literally
            # "Developer ID Application: <name> (<team>)". Grepping the
            # Authority chain is more reliable than parsing --requirements,
            # which renders as OIDs ("certificate leaf[field.1.2.840.…]").
            if ! echo "$cs_dump" | grep -qE '^Authority=Developer ID Application:'; then
                fail "release mode requires Developer ID Application signature"
            fi
            # Secure timestamp is mandatory for notarization.
            if ! echo "$cs_dump" | grep -q '^Timestamp='; then
                fail "release mode requires --timestamp signature (notarytool will reject without)"
            fi
            if ! xcrun stapler validate "$APP_BUNDLE" >/dev/null 2>&1; then
                fail "release mode requires stapled notarization"
            fi
        fi
    fi
fi

# --- Conclusion --------------------------------------------------------------

if [ "$fails" -eq 0 ]; then
    echo "audit: PASS ($APP_BUNDLE)"
    exit 0
fi

echo "audit: FAIL — $fails issue(s) found in $APP_BUNDLE" >&2
exit 1

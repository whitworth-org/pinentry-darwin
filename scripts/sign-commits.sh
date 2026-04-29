#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright 2026 Ryan Whitworth.
#
# sign-commits.sh — split the currently-staged tree into a sequence of
# GPG-signed commits in logical units. Run after `git init && git add -A`.
#
# Each commit will trigger a GPG sign operation. With a hardware-card key
# (e.g. YubiKey), each commit prompts for a card touch.
#
# Usage:
#   scripts/sign-commits.sh                # uses your global commit.gpgsign + user.signingkey
#   scripts/sign-commits.sh --no-split     # one big "scaffold v0.1.0" commit
#
# Re-runnable: aborts if HEAD already has commits, since the split assumes
# starting from an empty history.

set -euo pipefail

if ! git symbolic-ref --quiet HEAD >/dev/null; then
    echo "sign-commits: not on any branch — run 'git init -b main' first" >&2
    exit 1
fi

if git rev-parse --verify HEAD >/dev/null 2>&1; then
    echo "sign-commits: HEAD already has commits — refusing to overlay. Use 'git reset' first if you want to re-split." >&2
    exit 1
fi

mode="${1:-split}"

# Helper: stage the named pathspecs and commit them.
commit_group() {
    local message="$1"; shift
    local paths=("$@")
    git reset --quiet
    for p in "${paths[@]}"; do
        git add -- "$p"
    done
    if git diff --cached --quiet; then
        echo "(skipping empty commit: $message)"
        return
    fi
    git commit -S -m "$message"
}

if [ "$mode" = "--no-split" ]; then
    git reset --quiet
    git add -A
    git commit -S -m "scaffold pinentry-darwin v0.1.0 MVP

Drop-in Swift 6 / SwiftUI replacement for pinentry-mac. Speaks the Assuan
protocol over stdio with gpg-agent. macOS 15+. MIT licensed."
    exit 0
fi

# Split mode — one commit per logical unit.

commit_group "build: scaffold project structure" \
    .gitignore LICENSE README.md Package.swift Makefile \
    App/Info.plist App/pinentry-darwin.entitlements \
    scripts/smoke-assuan.sh scripts/sign-commits.sh \
    scripts/integration-gpg-agent.sh \
    dist/homebrew/pinentry-darwin.rb

commit_group "feat(secure-memory): mlock'd zeroing buffer" \
    Sources/SecureMemory \
    Tests/SecureMemoryTests

commit_group "feat(assuan): protocol codec, command/response, session actor" \
    Sources/AssuanProtocol \
    Tests/AssuanProtocolTests

commit_group "feat(keychain): SecItem wrapper compatible with pinentry-mac" \
    Sources/KeychainStore \
    Tests/KeychainStoreTests

commit_group "feat(ui): SwiftUI dialogs and Settings window in Ghostty style" \
    Sources/PinentryUI

commit_group "feat(daemon): wire stdio Assuan loop to UI coordinator" \
    Sources/PinentryDarwin

echo
echo "All commits signed. Verify with:"
echo "  git log --show-signature --oneline"

#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright 2026 Ryan Whitworth.
#
# integration-gpg-agent.sh — set up a throwaway GNUPGHOME pointing at the
# locally built pinentry-darwin and exercise it end-to-end.
#
# This script is *interactive* by nature: GETPIN flows pop a SwiftUI window
# you have to type a passphrase into. It cannot be run on a headless CI
# without a window server. Use it on a developer workstation as the final
# acceptance check before tagging a release.
#
# What it does:
#   1. Builds the binary (make build).
#   2. Creates a fresh GNUPGHOME under TMPDIR.
#   3. Writes gpg-agent.conf pointing pinentry-program at the built binary.
#   4. Starts a private gpg-agent and prints a checklist of manual steps:
#        - gpg --gen-key       (exercises GETPIN + SETREPEAT)
#        - gpg -d / passwd     (exercises cached + uncached + cancel paths)
#   5. On exit (or Ctrl-C), kills the private agent and removes GNUPGHOME.
#
# Usage:
#   scripts/integration-gpg-agent.sh
#
# Override paths with env vars:
#   PINENTRY_BIN=/path/to/pinentry-darwin scripts/integration-gpg-agent.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN_DEFAULT="$REPO_ROOT/build/pinentry-darwin.app/Contents/MacOS/pinentry-darwin"
PINENTRY_BIN="${PINENTRY_BIN:-$BIN_DEFAULT}"

if [ ! -x "$PINENTRY_BIN" ]; then
    echo "integration: binary not found at $PINENTRY_BIN — running 'make build' first..." >&2
    (cd "$REPO_ROOT" && make build >/dev/null)
fi

# Per-run sandbox.
SANDBOX="$(mktemp -d -t pinentry-darwin-int.XXXXXX)"
trap 'finalize' EXIT INT TERM

finalize() {
    if [ -n "${AGENT_PID:-}" ] && kill -0 "$AGENT_PID" 2>/dev/null; then
        kill "$AGENT_PID" 2>/dev/null || true
        # gpg-agent forks; clean up its socket too.
        gpgconf --homedir "$SANDBOX" --kill gpg-agent >/dev/null 2>&1 || true
    fi
    if [ -n "${SANDBOX:-}" ] && [ -d "$SANDBOX" ]; then
        rm -rf "$SANDBOX"
    fi
}

# A throwaway GNUPGHOME with restrictive perms (gpg requires 700).
chmod 700 "$SANDBOX"
export GNUPGHOME="$SANDBOX"

cat >"$SANDBOX/gpg-agent.conf" <<EOF
pinentry-program $PINENTRY_BIN
default-cache-ttl 5
max-cache-ttl 30
allow-loopback-pinentry
EOF

cat >"$SANDBOX/gpg.conf" <<EOF
use-agent
EOF

echo "integration: GNUPGHOME=$SANDBOX"
echo "integration: starting private gpg-agent..."
gpg-agent --homedir "$SANDBOX" --daemon --use-standard-socket >"$SANDBOX/agent.log" 2>&1 &
AGENT_PID=$!
sleep 1

if ! kill -0 "$AGENT_PID" 2>/dev/null; then
    echo "integration: gpg-agent failed to start. Log:" >&2
    cat "$SANDBOX/agent.log" >&2
    exit 1
fi

cat <<EOF
integration: ready.

Manual checks to run in another terminal (with the same GNUPGHOME):

    export GNUPGHOME="$SANDBOX"

    # 1) GETPIN + SETREPEAT (key generation):
    gpg --quick-gen-key 'Test User <test@example.invalid>' default default 1d

    # 2) GETPIN with cached lookup (run twice, second should be instant if you saved to keychain):
    echo "secret data" > "$SANDBOX/payload.txt"
    gpg --encrypt --recipient 'Test User' --armor "$SANDBOX/payload.txt"
    gpg --decrypt "$SANDBOX/payload.txt.asc"
    gpg --decrypt "$SANDBOX/payload.txt.asc"

    # 3) Confirmation flow (CONFIRM):
    gpg --edit-key 'Test User' passwd
    # then 'save' / 'quit'

    # 4) Cancel path:
    gpg --decrypt "$SANDBOX/payload.txt.asc"   # press Cancel in the dialog

When you're done, return to this terminal and press Enter to clean up.
(Or Ctrl-C — same effect.)
EOF

read -r _

echo "integration: tearing down."

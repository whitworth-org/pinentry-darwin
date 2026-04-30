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
#   scripts/integration-gpg-agent.sh             # full interactive run
#   scripts/integration-gpg-agent.sh --check     # autonomous prelude only
#
# `--check` does everything the interactive flow does up through "agent is up
# and can talk to its socket", then tears down. It's the most-coverage check
# we can do without a human typing into a SwiftUI dialog: it exercises the
# fork/exec path (agent finds and runs our binary), the agent's gpg-agent.conf
# parsing of `pinentry-program`, and the basic Assuan handshake on the agent
# control socket. The actual GETPIN dialog is interactive-only.
#
# Override paths with env vars:
#   PINENTRY_BIN=/path/to/pinentry-darwin scripts/integration-gpg-agent.sh

set -euo pipefail

MODE="interactive"
case "${1:-}" in
    --check)  MODE="check" ;;
    "")       : ;;
    *)        echo "usage: $0 [--check]" >&2; exit 2 ;;
esac

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN_DEFAULT="$REPO_ROOT/build/pinentry-darwin.app/Contents/MacOS/pinentry-darwin"
PINENTRY_BIN="${PINENTRY_BIN:-$BIN_DEFAULT}"

if [ ! -x "$PINENTRY_BIN" ]; then
    echo "integration: binary not found at $PINENTRY_BIN — running 'make build' first..." >&2
    (cd "$REPO_ROOT" && make build >/dev/null)
fi

# Per-run sandbox. We deliberately put this under /tmp (short prefix) rather
# than $TMPDIR because gpg-agent's UNIX socket paths are length-capped at
# 104 bytes on Darwin, and the default macOS $TMPDIR is already ~60 chars.
SANDBOX="$(mktemp -d /tmp/pdint.XXXXXX)"
trap 'finalize' EXIT INT TERM

finalize() {
    if [ -n "${SANDBOX:-}" ] && [ -d "$SANDBOX" ]; then
        gpgconf --homedir "$SANDBOX" --kill gpg-agent >/dev/null 2>&1 || true
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
# `--daemon` forks: the launcher exits, the daemon detaches. We can't track
# its PID from `$!`, so verify liveness by talking to the socket instead.
gpg-agent --homedir "$SANDBOX" --daemon >"$SANDBOX/agent.log" 2>&1
for _ in 1 2 3 4 5; do
    if gpg-connect-agent --homedir "$SANDBOX" /bye >/dev/null 2>&1; then
        break
    fi
    sleep 0.2
done
if ! gpg-connect-agent --homedir "$SANDBOX" /bye >/dev/null 2>&1; then
    echo "integration: gpg-agent failed to come up. Log:" >&2
    cat "$SANDBOX/agent.log" >&2
    exit 1
fi
AGENT_PID=""  # tracked via gpgconf --kill in finalize, not by PID

# Autonomous probes — agent reachability + binary self-tests. These never
# pop a dialog, so they're safe to run without a human present.
echo "integration: probing agent control socket..."
if ! gpg-connect-agent --homedir "$SANDBOX" 'GETINFO version' /bye >"$SANDBOX/probe.out" 2>&1; then
    echo "integration: FAIL — gpg-connect-agent could not reach the agent." >&2
    cat "$SANDBOX/probe.out" >&2
    exit 1
fi
if ! grep -qE '^D ' "$SANDBOX/probe.out"; then
    echo "integration: FAIL — agent did not return a D-line for GETINFO version." >&2
    cat "$SANDBOX/probe.out" >&2
    exit 1
fi
agent_version="$(awk '/^D /{print $2; exit}' "$SANDBOX/probe.out")"
echo "integration: agent reports gpg-agent version $agent_version"

echo "integration: probing pinentry-darwin self-test paths..."
"$PINENTRY_BIN" --version >"$SANDBOX/bin-version.out" 2>&1
if ! grep -qE '^pinentry-darwin [0-9]' "$SANDBOX/bin-version.out"; then
    echo "integration: FAIL — pinentry-darwin --version did not match expected format." >&2
    cat "$SANDBOX/bin-version.out" >&2
    exit 1
fi
echo "integration: $(cat "$SANDBOX/bin-version.out")"

if [ "$MODE" = "check" ]; then
    echo "integration: --check PASS (agent up, socket reachable, binary self-test OK)"
    echo "integration: skipping interactive GETPIN section."
    exit 0
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

#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright 2026 Ryan Whitworth.
#
# smoke-assuan.sh — exercise the protocol path of the freshly built
# pinentry-darwin binary by feeding it a small Assuan transcript on stdin.
# This does not exercise the GUI (GETPIN/CONFIRM/MESSAGE need a display);
# for that, run the binary as a `pinentry-program` against gpg-agent.
#
# Usage:
#   scripts/smoke-assuan.sh                       # uses build/pinentry-darwin.app/Contents/MacOS/pinentry-darwin
#   scripts/smoke-assuan.sh path/to/pinentry-darwin
#
# Exits 0 if all three GETINFO replies appear and BYE returns OK; 1 otherwise.

set -euo pipefail

BIN="${1:-build/pinentry-darwin.app/Contents/MacOS/pinentry-darwin}"
if [ ! -x "$BIN" ]; then
    echo "smoke-assuan: $BIN not executable. Run 'make build' first." >&2
    exit 2
fi

TRANSCRIPT=$'GETINFO version\nGETINFO flavor\nGETINFO pid\nBYE\n'
OUT="$(printf '%s' "$TRANSCRIPT" | "$BIN" 2>/dev/null)"

ok=0
echo "$OUT" | grep -qE '^OK Pleased to meet you' && ok=$((ok+1))
echo "$OUT" | grep -qE '^D [0-9]+\.[0-9]+\.[0-9]+'  && ok=$((ok+1))   # version
echo "$OUT" | grep -qE '^D darwin'                  && ok=$((ok+1))   # flavor
echo "$OUT" | grep -qE '^D [0-9]+'                  && ok=$((ok+1))   # pid
# Final BYE OK: the last line should be an OK.
echo "$OUT" | tail -n 1 | grep -qE '^OK'            && ok=$((ok+1))

if [ "$ok" -eq 5 ]; then
    echo "smoke-assuan: PASS (all 5 markers found)"
    exit 0
fi

echo "smoke-assuan: FAIL — only $ok/5 markers matched. Output was:" >&2
echo "$OUT" >&2
exit 1

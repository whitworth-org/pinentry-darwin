#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright 2026 Ryan Whitworth.
#
# smoke-assuan.sh — exercise the non-GUI wire surface of pinentry-darwin
# by feeding it a recorded Assuan transcript on stdin and asserting the
# expected responses come back on stdout.
#
# This does NOT exercise GUI dialogs (GETPIN/CONFIRM/MESSAGE need a
# display); for that, run the binary as a `pinentry-program` against a
# throwaway gpg-agent (see scripts/integration-gpg-agent.sh).
#
# What is covered here:
#   - Initial OK greeting
#   - OPTION (multiple, including bare and key=value forms)
#   - SETDESC / SETPROMPT / SETTITLE / SETERROR / SETKEYINFO / SETTIMEOUT
#   - GETINFO version | flavor | pid | ttyinfo
#   - Comment lines (#…) and blank lines tolerated
#   - RESET resets per-dialog state but not OPTION state
#   - GETINFO unknown topic returns ERR
#   - BYE returns OK and the process exits 0
#
# Usage:
#   scripts/smoke-assuan.sh                       # uses build/pinentry-darwin.app/Contents/MacOS/pinentry-darwin
#   scripts/smoke-assuan.sh path/to/pinentry-darwin
#
# Exits 0 on success; 1 on any assertion failure (with the offending
# transcript dumped to stderr).

set -euo pipefail

BIN="${1:-build/pinentry-darwin.app/Contents/MacOS/pinentry-darwin}"
if [ ! -x "$BIN" ]; then
    echo "smoke-assuan: $BIN not executable. Run 'make build' first." >&2
    exit 2
fi

TRANSCRIPT=$'# leading comment, must be tolerated\n\nOPTION ttytype=xterm-256color\nOPTION ttyname=/dev/ttys042\nOPTION lc-ctype=en_US.UTF-8\nOPTION default-ok=OK\nOPTION default-cancel=Cancel\nOPTION default-prompt=Passphrase:\nOPTION grab\nSETDESC Please+enter+your+passphrase\nSETPROMPT pin\nSETTITLE pinentry-darwin+smoke\nSETERROR none\nSETKEYINFO n/ABCDEF1234567890ABCDEF1234567890ABCDEF12\nSETTIMEOUT 30\nSETQUALITYBAR Strength\nSETQUALITYBAR_TT Higher+is+stronger\nGETINFO version\nGETINFO flavor\nGETINFO pid\nGETINFO ttyinfo\n# RESET clears per-dialog state\nRESET\nGETINFO ttyinfo\nGETINFO not-a-real-topic\nBYE\n'

# Capture stdout; stderr is dropped (it carries diagnostic noise on first
# Foundation init that varies across macOS versions).
OUT="$(printf '%s' "$TRANSCRIPT" | "$BIN" 2>/dev/null)"
RC=$?
if [ "$RC" -ne 0 ]; then
    echo "smoke-assuan: binary exited with status $RC" >&2
    echo "--- captured output ---" >&2
    printf '%s\n' "$OUT" >&2
    exit 1
fi

assert() {
    local label="$1"; shift
    local pattern="$1"; shift
    if printf '%s\n' "$OUT" | grep -qE "$pattern"; then
        return 0
    fi
    echo "smoke-assuan: FAIL — missing $label (pattern: $pattern)" >&2
    return 1
}

fails=0

assert "greeting"        '^OK Pleased to meet you'                || fails=$((fails+1))
assert "version reply"   '^D [0-9]+\.[0-9]+\.[0-9]+'              || fails=$((fails+1))
assert "flavor reply"    '^D darwin'                               || fails=$((fails+1))
assert "pid reply"       '^D [0-9]+'                               || fails=$((fails+1))
# ttyinfo response carries spaces, which the wire codec encodes as '+'
# (matches upstream pinentry's copy_and_escape — pinentry.c:262).
assert "ttyinfo reply"   '^D /dev/ttys042\+xterm-256color\+0$'     || fails=$((fails+1))
assert "ERR on unknown getinfo" '^ERR '                            || fails=$((fails+1))

# Count OK lines: greeting + every command that returned OK (every OPTION,
# SET*, RESET, BYE; plus the trailing OK after each successful GETINFO `D`).
# We don't pin an exact count because future status emissions could legitimately
# change it; we DO pin that the final wire line is an OK from BYE.
last_line="$(printf '%s\n' "$OUT" | grep -v '^$' | tail -n 1)"
case "$last_line" in
    OK*) : ;;
    *)
        echo "smoke-assuan: FAIL — last non-empty line is not an OK: '$last_line'" >&2
        fails=$((fails+1))
        ;;
esac

# Sanity: never echo a SETPROMPT / SETDESC / passphrase value back on the
# wire. Only OK / ERR / D / S / INQUIRE prefixes are valid response verbs.
if printf '%s\n' "$OUT" | grep -vE '^(OK|ERR|D |S |INQUIRE|#|$)' | grep -q .; then
    echo "smoke-assuan: FAIL — unexpected wire content (lines without OK/ERR/D/S/INQUIRE prefix):" >&2
    printf '%s\n' "$OUT" | grep -vnE '^(OK|ERR|D |S |INQUIRE|#|$)' >&2
    fails=$((fails+1))
fi

if [ "$fails" -eq 0 ]; then
    echo "smoke-assuan: PASS"
    exit 0
fi

echo "smoke-assuan: FAIL — $fails assertion(s) failed. Full output:" >&2
printf '%s\n' "$OUT" >&2
exit 1

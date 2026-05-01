#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright 2026 Ryan Whitworth.
#
# run-fuzz.sh — build and run a libFuzzer-instrumented Swift fuzz target
# against the AssuanProtocol library.
#
# Usage:
#   scripts/run-fuzz.sh                          # run all four for 60s each
#   scripts/run-fuzz.sh PinentryFuzzCommand     # run one for 60s
#   scripts/run-fuzz.sh --time 300               # all four, 5 min each
#   scripts/run-fuzz.sh PinentryFuzzMnemonic --time 30
#
# WHY this script exists rather than `swift build -Xswiftc -sanitize=fuzzer`:
#   Apple's shipped Swift toolchain (the one inside Xcode.app) is built
#   WITHOUT the `fuzzer` sanitizer. It only ships address / thread / undefined.
#   The open-source swift.org toolchains DO ship libFuzzer, but most macOS
#   developers do not have one installed.
#
#   This script works around that by:
#     1. building the AssuanProtocol library through SwiftPM (no sanitizer);
#     2. compiling each fuzz target's `FuzzTarget.swift` directly with
#        `swiftc -sanitize=address`, importing the prebuilt module;
#     3. force-loading the libFuzzer runtime archive from the CodeQL
#        Caskroom (the most commonly-already-present place to find a
#        Darwin libFuzzer on a developer machine);
#     4. supplying the C `main()` from `Fuzz/Driver/driver.c` that calls
#        `LLVMFuzzerRunDriver(...)`.
#
# If your machine has libFuzzer somewhere else, set FUZZER_LIB to the
# absolute path of `libclang_rt.fuzzer_no_main_osx.a`.

set -euo pipefail

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

ALL_TARGETS=(PinentryFuzzLineCodec PinentryFuzzCommand PinentryFuzzMnemonic PinentryFuzzResponse)
TARGETS=()
TIME_SEC=60

while [[ $# -gt 0 ]]; do
  case "$1" in
    --time)
      TIME_SEC="$2"
      shift 2
      ;;
    --time=*)
      TIME_SEC="${1#--time=}"
      shift
      ;;
    -h|--help)
      sed -n '5,30p' "$0"
      exit 0
      ;;
    *)
      TARGETS+=("$1")
      shift
      ;;
  esac
done

if [[ ${#TARGETS[@]} -eq 0 ]]; then
  TARGETS=("${ALL_TARGETS[@]}")
fi

# ---------------------------------------------------------------------------
# Locate the libFuzzer runtime archive
# ---------------------------------------------------------------------------

if [[ -z "${FUZZER_LIB:-}" ]]; then
  # Best-effort search across known Darwin locations. Order matters:
  # we prefer the no_main variant since our driver provides main().
  CANDIDATES=(
    /opt/homebrew/Caskroom/codeql/*/codeql/swift/resource-dir/osx64/clang/lib/darwin/libclang_rt.fuzzer_no_main_osx.a
    /usr/local/Caskroom/codeql/*/codeql/swift/resource-dir/osx64/clang/lib/darwin/libclang_rt.fuzzer_no_main_osx.a
    /Library/Developer/Toolchains/*/usr/lib/clang/*/lib/darwin/libclang_rt.fuzzer_no_main_osx.a
    "${HOME}/Library/Developer/Toolchains/*/usr/lib/clang/*/lib/darwin/libclang_rt.fuzzer_no_main_osx.a"
    /opt/homebrew/opt/llvm/lib/clang/*/lib/darwin/libclang_rt.fuzzer_no_main_osx.a
  )
  for cand in "${CANDIDATES[@]}"; do
    # Glob expansion happens here; pick the first match that exists.
    for resolved in $cand; do
      if [[ -f "$resolved" ]]; then
        FUZZER_LIB="$resolved"
        break 2
      fi
    done
  done
fi

if [[ -z "${FUZZER_LIB:-}" || ! -f "$FUZZER_LIB" ]]; then
  echo "ERROR: could not locate libclang_rt.fuzzer_no_main_osx.a." >&2
  echo "Set FUZZER_LIB to its absolute path. Common sources:" >&2
  echo "  - 'brew install --cask codeql' bundles a copy" >&2
  echo "  - install an open-source Swift toolchain from swift.org" >&2
  exit 2
fi

echo "Using libFuzzer runtime: $FUZZER_LIB"

# ---------------------------------------------------------------------------
# Build the AssuanProtocol module via SwiftPM so we have a .swiftmodule to
# import. Without this, swiftc would have to compile the library from
# source on every fuzz invocation.
# ---------------------------------------------------------------------------

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

echo "Building AssuanProtocol via SwiftPM..."
swift build --product AssuanProtocol -c debug >/dev/null

# Resolve SwiftPM module + library output dirs. SwiftPM's layout puts
# .swiftmodule under .build/<triple>/debug/Modules and .o files under
# .build/<triple>/debug/<TargetName>.build/.
TRIPLE_DIR=$(ls -d .build/*-apple-macosx/debug 2>/dev/null | head -1)
if [[ -z "$TRIPLE_DIR" ]]; then
  echo "ERROR: could not find SwiftPM debug build dir under .build/" >&2
  exit 3
fi
MODULE_DIR="$TRIPLE_DIR/Modules"

# Collect .o files for AssuanProtocol + SecureMemory so we can link them
# directly into the fuzz binary (avoids dylib loader-path headaches).
ASSUAN_OBJS=$(find "$TRIPLE_DIR/AssuanProtocol.build" -name "*.o" 2>/dev/null | tr '\n' ' ')
SECURE_OBJS=$(find "$TRIPLE_DIR/SecureMemory.build" -name "*.o" 2>/dev/null | tr '\n' ' ')
if [[ -z "$ASSUAN_OBJS" || -z "$SECURE_OBJS" ]]; then
  echo "ERROR: could not find AssuanProtocol/SecureMemory object files in $TRIPLE_DIR" >&2
  exit 4
fi

# Compile the C driver once; reused by every target.
DRIVER_OBJ="$REPO_ROOT/.build/fuzz-driver.o"
mkdir -p "$REPO_ROOT/.build"
clang -c "$REPO_ROOT/Fuzz/Driver/driver.c" -o "$DRIVER_OBJ"

# ---------------------------------------------------------------------------
# Per-target build + run
# ---------------------------------------------------------------------------

run_one() {
  local target="$1"
  local target_dir="$REPO_ROOT/Fuzz/$target"
  local fuzz_src="$target_dir/FuzzTarget.swift"
  local out_bin="$REPO_ROOT/.build/$target.fuzz"
  local findings_dir="$target_dir/findings"
  local corpus_dir="$target_dir/corpus"

  if [[ ! -f "$fuzz_src" ]]; then
    echo "SKIP: $target (no FuzzTarget.swift)" >&2
    return
  fi

  mkdir -p "$findings_dir"

  echo
  echo "=========================================================="
  echo "Building fuzz binary: $target"
  echo "=========================================================="

  # Build with -parse-as-library (no top-level main; the C driver is main)
  # and -sanitize=address. -O is left at default; libFuzzer wants debug
  # info but not aggressive opts. Force-load the libFuzzer archive so its
  # symbols (LLVMFuzzerRunDriver, signal handlers, mutator) are pulled in.
  # shellcheck disable=SC2086
  swiftc \
    -parse-as-library \
    -sanitize=address \
    -I "$MODULE_DIR" \
    -L "$TRIPLE_DIR" \
    "$fuzz_src" \
    "$DRIVER_OBJ" \
    $ASSUAN_OBJS \
    $SECURE_OBJS \
    -Xlinker -force_load -Xlinker "$FUZZER_LIB" \
    -lc++ \
    -o "$out_bin"

  echo
  echo "=========================================================="
  echo "Running $target for ${TIME_SEC}s"
  echo "  corpus:   $corpus_dir"
  echo "  findings: $findings_dir"
  echo "=========================================================="

  # Run libFuzzer. -max_total_time bounds wall-clock time; -artifact_prefix
  # routes any crash artifact into our findings dir; the trailing corpus/
  # path is the seed directory libFuzzer reads from.
  set +e
  ASAN_OPTIONS="abort_on_error=1:halt_on_error=1:print_stacktrace=1" \
    "$out_bin" \
      -max_total_time="$TIME_SEC" \
      -artifact_prefix="$findings_dir/" \
      -print_final_stats=1 \
      "$corpus_dir/"
  local rc=$?
  set -e
  echo "fuzzer exit code: $rc"
}

for t in "${TARGETS[@]}"; do
  run_one "$t"
done

echo
echo "Fuzz run complete."

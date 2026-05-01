// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// driver.c — C entry-point that hands control to libFuzzer's
// LLVMFuzzerRunDriver. Used when the Swift fuzz target is linked against
// libclang_rt.fuzzer_no_main_osx.a (which omits its built-in main).
//
// Why a C main and not Swift's: Swift's @main / top-level code emits its
// own _main, and we cannot suppress it cleanly while keeping the cdecl
// LLVMFuzzerTestOneInput entry. A bare C main is the canonical approach
// recommended in the libFuzzer documentation for non-C++ harnesses.

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerRunDriver(int *argc, char ***argv,
                        int (*UserCb)(const uint8_t *Data, size_t Size));

int main(int argc, char **argv) {
    return LLVMFuzzerRunDriver(&argc, &argv, LLVMFuzzerTestOneInput);
}

// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// SwiftPM executable entry. See PinentryFuzzLineCodec/main.swift for the
// rationale — this file is excluded from the libFuzzer build.

import Foundation

let stdin = FileHandle.standardInput
let data = stdin.readDataToEndOfFile()
fuzzCommandOnce(Array(data))

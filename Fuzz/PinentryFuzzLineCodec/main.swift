// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// SwiftPM executable entry. When built via `swift build --product
// PinentryFuzzLineCodec`, this reads stdin and runs the fuzz function
// once. This is NOT used by the libFuzzer build path — that path
// excludes main.swift via direct swiftc invocation in scripts/run-fuzz.sh.
//
// Useful for: regression-testing a single saved corpus input outside
// the libFuzzer harness, e.g.:
//   swift run PinentryFuzzLineCodec < Fuzz/PinentryFuzzLineCodec/findings/crash-XXX

import Foundation

let stdin = FileHandle.standardInput
let data = stdin.readDataToEndOfFile()
fuzzLineCodecOnce(Array(data))

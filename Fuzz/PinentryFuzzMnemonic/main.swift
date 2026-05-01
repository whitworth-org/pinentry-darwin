// SPDX-License-Identifier: MIT
// Copyright 2026 Ryan Whitworth.
//
// SwiftPM executable entry. Excluded from the libFuzzer build path.

import Foundation

let stdin = FileHandle.standardInput
let data = stdin.readDataToEndOfFile()
fuzzMnemonicOnce(Array(data))

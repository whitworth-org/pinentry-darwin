// swift-tools-version: 6.0
//
// pinentry-darwin
//
// A Swift 6 / SwiftUI replacement for pinentry-mac. Layered targets enforce a
// clear trust boundary: SecureMemory and AssuanProtocol are pure-Swift, no UI,
// and exhaustively tested. KeychainStore wraps the macOS Security framework.
// PinentryUI hosts the SwiftUI views. The executable target wires them up.
//
// HARD RULES (per project CLAUDE.md):
//   - No third-party dependencies. Standard library + Apple frameworks only.
//   - Swift 6 language mode, strict concurrency.
//   - macOS 15.0+ (for the latest Observation / SwiftUI / SecItem APIs).

import PackageDescription

let package = Package(
    name: "pinentry-darwin",
    platforms: [
        .macOS(.v15)
    ],
    products: [
        .executable(name: "pinentry-darwin", targets: ["PinentryDarwin"]),
        .library(name: "SecureMemory", targets: ["SecureMemory"]),
        .library(name: "AssuanProtocol", targets: ["AssuanProtocol"]),
        .library(name: "KeychainStore", targets: ["KeychainStore"]),
        .library(name: "PinentryUI", targets: ["PinentryUI"]),
    ],
    dependencies: [],
    targets: [
        .target(
            name: "SecureMemory",
            path: "Sources/SecureMemory"
        ),
        .target(
            name: "AssuanProtocol",
            dependencies: ["SecureMemory"],
            path: "Sources/AssuanProtocol"
        ),
        .target(
            name: "KeychainStore",
            dependencies: ["SecureMemory"],
            path: "Sources/KeychainStore"
        ),
        .target(
            name: "PinentryUI",
            dependencies: [
                "SecureMemory",
                "AssuanProtocol",
                "KeychainStore",
            ],
            path: "Sources/PinentryUI"
        ),
        .executableTarget(
            name: "PinentryDarwin",
            dependencies: [
                "SecureMemory",
                "AssuanProtocol",
                "KeychainStore",
                "PinentryUI",
            ],
            path: "Sources/PinentryDarwin"
        ),
        .testTarget(
            name: "SecureMemoryTests",
            dependencies: ["SecureMemory"],
            path: "Tests/SecureMemoryTests"
        ),
        .testTarget(
            name: "AssuanProtocolTests",
            dependencies: ["AssuanProtocol", "SecureMemory"],
            path: "Tests/AssuanProtocolTests"
        ),
        .testTarget(
            name: "KeychainStoreTests",
            dependencies: ["KeychainStore", "SecureMemory"],
            path: "Tests/KeychainStoreTests"
        ),
        .testTarget(
            name: "PinentryUITests",
            dependencies: ["PinentryUI", "SecureMemory"],
            path: "Tests/PinentryUITests"
        ),

        // MARK: - Fuzz harnesses
        //
        // Each fuzz target is a SwiftPM executable that exposes a Swift
        // function `fuzz<Module>Once([UInt8])` plus a `@_cdecl` libFuzzer
        // entry point in `FuzzTarget.swift`, and a `main.swift` that reads
        // stdin and runs the function once. `swift run <target>` is the
        // regression-replay path (feed a saved crash artifact via stdin).
        // The libFuzzer build path lives in `scripts/run-fuzz.sh`, which
        // invokes `swiftc` directly with `-sanitize=address`, force-loads
        // the libFuzzer runtime, and excludes `main.swift` (since libFuzzer
        // provides its own main via `Fuzz/Driver/driver.c`).
        .executableTarget(
            name: "PinentryFuzzLineCodec",
            dependencies: ["AssuanProtocol", "SecureMemory"],
            path: "Fuzz/PinentryFuzzLineCodec",
            exclude: ["corpus", "findings"]
        ),
        .executableTarget(
            name: "PinentryFuzzCommand",
            dependencies: ["AssuanProtocol"],
            path: "Fuzz/PinentryFuzzCommand",
            exclude: ["corpus", "findings"]
        ),
        .executableTarget(
            name: "PinentryFuzzMnemonic",
            dependencies: ["AssuanProtocol"],
            path: "Fuzz/PinentryFuzzMnemonic",
            exclude: ["corpus", "findings"]
        ),
        .executableTarget(
            name: "PinentryFuzzResponse",
            dependencies: ["AssuanProtocol", "SecureMemory"],
            path: "Fuzz/PinentryFuzzResponse",
            exclude: ["corpus", "findings"]
        ),
    ],
    swiftLanguageModes: [.v6]
)

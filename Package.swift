// swift-tools-version: 6.2
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
//   - macOS 26.0 floor, matching the .app's `LSMinimumSystemVersion`.

import PackageDescription

// Swift 7 language-mode behaviours, adopted early so the code is already
// correct when the mode becomes the default, plus strict memory safety
// (SE-0458) so every unsafe construct is explicit. Applied to every target.
let strictSettings: [SwiftSetting] = [
    .enableUpcomingFeature("NonisolatedNonsendingByDefault"),
    .enableUpcomingFeature("InferIsolatedConformances"),
    .enableUpcomingFeature("ImmutableWeakCaptures"),
    .enableUpcomingFeature("ExistentialAny"),
    .enableUpcomingFeature("InternalImportsByDefault"),
    .enableUpcomingFeature("MemberImportVisibility"),
    .strictMemorySafety(),
]

let package = Package(
    name: "pinentry-darwin",
    platforms: [
        .macOS(.v26)
    ],
    products: [
        .executable(name: "pinentry-darwin", targets: ["PinentryDarwin"]),
        .library(name: "SecureMemory", targets: ["SecureMemory"]),
        .library(name: "AssuanProtocol", targets: ["AssuanProtocol"]),
        .library(name: "KeychainStore", targets: ["KeychainStore"]),
        .library(name: "SSHIdentity", targets: ["SSHIdentity"]),
        .library(name: "PinentryUI", targets: ["PinentryUI"]),
    ],
    dependencies: [],
    targets: [
        .target(
            name: "SecureMemory",
            path: "Sources/SecureMemory",
            swiftSettings: strictSettings
        ),
        .target(
            name: "AssuanProtocol",
            dependencies: ["SecureMemory"],
            path: "Sources/AssuanProtocol",
            swiftSettings: strictSettings
        ),
        .target(
            name: "KeychainStore",
            dependencies: ["SecureMemory"],
            path: "Sources/KeychainStore",
            swiftSettings: strictSettings
        ),
        .target(
            name: "SSHIdentity",
            dependencies: [],
            path: "Sources/SSHIdentity",
            swiftSettings: strictSettings
        ),
        .target(
            name: "PinentryUI",
            dependencies: [
                "SecureMemory",
                "AssuanProtocol",
                "KeychainStore",
                "SSHIdentity",
            ],
            path: "Sources/PinentryUI",
            swiftSettings: strictSettings
        ),
        .executableTarget(
            name: "PinentryDarwin",
            dependencies: [
                "SecureMemory",
                "AssuanProtocol",
                "KeychainStore",
                "PinentryUI",
            ],
            path: "Sources/PinentryDarwin",
            swiftSettings: strictSettings
        ),
        .executableTarget(
            name: "audit-bundle",
            dependencies: [],
            path: "Tools/AuditBundle",
            swiftSettings: strictSettings
        ),
        .testTarget(
            name: "SecureMemoryTests",
            dependencies: ["SecureMemory"],
            path: "Tests/SecureMemoryTests",
            swiftSettings: strictSettings
        ),
        .testTarget(
            name: "AssuanProtocolTests",
            dependencies: ["AssuanProtocol", "SecureMemory"],
            path: "Tests/AssuanProtocolTests",
            swiftSettings: strictSettings
        ),
        .testTarget(
            name: "KeychainStoreTests",
            dependencies: ["KeychainStore", "SecureMemory"],
            path: "Tests/KeychainStoreTests",
            swiftSettings: strictSettings
        ),
        .testTarget(
            name: "SSHIdentityTests",
            dependencies: ["SSHIdentity"],
            path: "Tests/SSHIdentityTests",
            swiftSettings: strictSettings
        ),
        .testTarget(
            name: "PinentryUITests",
            dependencies: ["PinentryUI", "KeychainStore", "SecureMemory"],
            path: "Tests/PinentryUITests",
            swiftSettings: strictSettings
        ),
        .testTarget(
            name: "PinentryDarwinTests",
            dependencies: ["PinentryDarwin"],
            path: "Tests/PinentryDarwinTests",
            swiftSettings: strictSettings
        ),
        .testTarget(
            name: "IntegrationSmokeTests",
            dependencies: [],
            path: "Tests/IntegrationSmokeTests",
            swiftSettings: strictSettings
        ),
        .testTarget(
            name: "AuditBundleTests",
            dependencies: [],
            path: "Tests/AuditBundleTests",
            swiftSettings: strictSettings
        ),
    ],
    swiftLanguageModes: [.v6]
)

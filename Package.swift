// swift-tools-version: 6.3

import PackageDescription

// SecureStore — a cross-platform abstraction over the operating system's secure credential
// storage. Every platform with a Swift-reachable secure store gets a native backend: Apple talks
// to Keychain Services, Windows to Credential Manager, Linux to the Secret Service via libsecret.
// Platforms whose store lives outside Swift — Android's Keystore, which is Java — register a
// backend at runtime through a C entry point instead.
//
// The name is deliberately not "Keychain": that is an Apple term, and this package's whole
// purpose is that callers should not have to know which platform they are on. The same reasoning
// applies to `SecureStoreConfiguration.namespace`, which is an opaque string rather than an
// Apple keychain access group.
let package = Package(
    name: "securestore-swift",
    platforms: [
        .iOS(.v13),
        .macOS(.v10_15),
        .tvOS(.v13),
        .watchOS(.v7),
        .visionOS(.v1),
    ],
    products: [
        .library(name: "SecureStore", targets: ["SecureStore"])
    ],
    targets: [
        // libsecret, reached through pkg-config. This is the package's only external
        // dependency, and it is deliberately scoped to one platform: the target dependency
        // below is conditional on Linux, so pkg-config is never consulted — and
        // `libsecret-1-dev` is never required — when building for anything else.
        .systemLibrary(
            name: "CSecret",
            path: "Sources/CSecret",
            pkgConfig: "libsecret-1",
            providers: [
                .apt(["libsecret-1-dev"]),
                .yum(["libsecret-devel"]),
            ]
        ),
        .target(
            name: "SecureStore",
            dependencies: [
                .target(name: "CSecret", condition: .when(platforms: [.linux]))
            ],
            path: "Sources/SecureStore",
            linkerSettings: [
                // `CredWriteW` and friends are declared by the Windows SDK headers that WinSDK
                // re-exports, but the import library still has to be linked explicitly.
                .linkedLibrary("advapi32", .when(platforms: [.windows]))
            ]
        ),
        .testTarget(
            name: "SecureStoreTests",
            dependencies: ["SecureStore"],
            path: "Tests/SecureStoreTests"
        ),
    ]
)

// swift-tools-version: 6.3

import PackageDescription

// SecureStore — a cross-platform abstraction over the operating system's secure credential
// storage. Apple platforms talk to Keychain Services directly; other hosts (Android's Keystore /
// EncryptedSharedPreferences, and anything else without a Swift-native secure store) register a
// backend at runtime through a C entry point.
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
        .target(name: "SecureStore", path: "Sources/SecureStore"),
        .testTarget(
            name: "SecureStoreTests",
            dependencies: ["SecureStore"],
            path: "Tests/SecureStoreTests"
        ),
    ]
)

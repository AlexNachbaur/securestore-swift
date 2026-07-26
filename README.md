# SecureStore

[![Build](https://github.com/AlexNachbaur/securestore-swift/actions/workflows/build.yml/badge.svg)](https://github.com/AlexNachbaur/securestore-swift/actions/workflows/build.yml)
[![Swift 6.3](https://img.shields.io/badge/Swift-6.3-orange.svg)](https://swift.org)
[![Platforms](https://img.shields.io/badge/Platforms-macOS%20%7C%20iOS%20%7C%20watchOS%20%7C%20tvOS%20%7C%20visionOS%20%7C%20Android-blue.svg)](#requirements)
[![License: MIT](https://img.shields.io/badge/License-MIT-lightgrey.svg)](LICENSE)

One secure-credential API for Swift, on Apple platforms and Android.

SecureStore gives you a single `SecureStore` protocol for reading and writing small secrets —
tokens, refresh credentials, keys. On Apple platforms it talks to Keychain Services directly. On
Android, where the secure store is Java-side, the host app registers a backend through a small C
entry point and Swift forwards to it. Callers never learn which platform they are on.

> **Status: pre-1.0.** The API is small and the behavioural contract is covered by a test suite
> that runs against every backend, but the API may still evolve before `1.0.0`. Breaking changes
> are called out in the [CHANGELOG](CHANGELOG.md).

## Why

If you share business logic between an iOS app and an Android app written in Swift, credential
storage is one of the first things that stops compiling. `Security` does not exist off Apple, and
the Android equivalent — Keystore, usually via `EncryptedSharedPreferences` — is a Java API with
no Swift bindings.

SecureStore solves that without dragging a Java-interop layer into your Swift code:

- **One protocol, six operations.** `set`, `data(for:)`, `remove`, `removeAll`, `allKeys` — the
  surface a token store actually needs, and nothing else.
- **No Apple concepts in the cross-platform API.** There is no `accessGroup` parameter. Sharing
  scope is an opaque `namespace` string, because Android has no App-Group equivalent and baking
  one platform's model into the API would defeat the purpose.
- **Errors are errors.** Every operation throws, including reads. A credential that is missing
  because the item was locked is a very different situation from one that was never written, and
  the API refuses to conflate them.
- **The host owns the Android implementation.** Swift never links a Java SDK; you register C
  callbacks once at startup.

## Installation

```swift
.package(url: "https://github.com/AlexNachbaur/securestore-swift.git", from: "0.1.0")
```

```swift
.target(name: "YourTarget", dependencies: [
    .product(name: "SecureStore", package: "securestore-swift")
])
```

## Usage

```swift
import SecureStore

let store = KeychainSecureStore(service: "com.example.auth")

try store.set(Data(token.utf8), for: "session")

if let data = try store.data(for: "session") {
    let token = String(decoding: data, as: UTF8.self)
}

try store.remove("session")
```

To stay platform-agnostic, depend on the protocol and construct the concrete store once:

```swift
func makeStore(service: String) -> any SecureStore {
    #if canImport(Security)
        KeychainSecureStore(service: service)
    #else
        HostSecureStore(service: service)
    #endif
}
```

### Sharing between processes

`namespace` scopes items beyond a single process. On Apple it maps to a keychain access group,
letting an app and its extensions read the same items:

```swift
KeychainSecureStore(service: "com.example.auth", namespace: "TEAMID.com.example.shared")
```

Hosts with no equivalent concept ignore it. Design your key layout so that a host which cannot
share is still correct — just less convenient.

## Android

On Android the secure store lives in Java, so the host registers an implementation at startup.
Swift calls out to it; it never calls into Java.

Register once, before any store is used — in practice from `Application.onCreate`, via a JNI
shim that calls the exported entry point:

```c
void securestore_register_host(
    int32_t (*set)(const char *service, const char *namespace_,
                   const char *key, const uint8_t *bytes, int32_t length),
    int32_t (*get)(const char *service, const char *namespace_, const char *key,
                   void *context,
                   void (*sink)(void *context, const uint8_t *bytes, int32_t length)),
    int32_t (*remove)(const char *service, const char *namespace_, const char *key),
    int32_t (*remove_all)(const char *service, const char *namespace_),
    int32_t (*all_keys)(const char *service, const char *namespace_,
                        void *context,
                        void (*sink)(void *context, const char *key)));
```

Two rules govern that ABI, and they are what make it safe:

1. **No heap pointers cross the boundary.** A host with a result invokes the supplied *sink* with
   a pointer and a length; Swift copies within the callback's lifetime and the host frees its own
   buffer when the call returns. Ownership never changes hands, so there is nothing to leak and
   nothing to double-free.
2. **Every operation returns a status.** `0` is success and `1` means "no such item" — not an
   error for reads or removals. Any other value is surfaced as
   `SecureStoreError.platform(code:)` carrying the host's own code, so a failure in the field can
   be traced to a specific platform error rather than a generic one.

Until a host registers, every operation throws `SecureStoreError.backendNotRegistered`. That is
deliberate: a store that silently appears to work while persisting nothing is far worse than a
loud failure.

See [docs/design/host-bridge-abi.md](docs/design/host-bridge-abi.md) for the full contract.

## Requirements

| Platform | Backend |
|---|---|
| iOS 13+ / macOS 10.15+ / watchOS 7+ / tvOS 13+ / visionOS 1+ | `KeychainSecureStore` — Keychain Services |
| Android | `HostSecureStore` — host-registered callbacks |

Swift 6.3+. Android builds use the official [Swift SDK for Android](https://www.swift.org/documentation/articles/swift-sdk-for-android-getting-started.html).

## Testing

The behavioural contract is written once and run against whichever backend the platform provides,
so Apple and Android cannot drift:

```bash
swift test                                              # Apple, against the real Keychain
swift test --swift-sdk aarch64-unknown-linux-android28  # Android, in an emulator
```

That suite already earned its keep: it caught that `SecItemDelete` deletes *one* matching item on
the macOS legacy keychain but *all* of them on iOS — a `removeAll` that silently left items
behind on one Apple platform and not another.

## License

MIT — see [LICENSE](LICENSE).

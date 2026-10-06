# SecureStore

[![Build](https://github.com/AlexNachbaur/securestore-swift/actions/workflows/build.yml/badge.svg)](https://github.com/AlexNachbaur/securestore-swift/actions/workflows/build.yml)
[![Swift 6.3](https://img.shields.io/badge/Swift-6.3-orange.svg)](https://swift.org)
[![Platforms](https://img.shields.io/badge/Platforms-macOS%20%7C%20iOS%20%7C%20watchOS%20%7C%20tvOS%20%7C%20visionOS%20%7C%20Linux%20%7C%20Windows%20%7C%20Android-blue.svg)](#requirements)
[![License: MIT](https://img.shields.io/badge/License-MIT-lightgrey.svg)](LICENSE)

One secure-credential API for Swift, on Apple platforms, Windows, Linux, and Android.

SecureStore gives you a single `SecureStore` protocol for reading and writing small secrets —
tokens, refresh credentials, keys. Every platform whose secure store is reachable from Swift
gets a native backend: Keychain Services on Apple, Credential Manager on Windows, the
freedesktop.org Secret Service on Linux. Android's store is Java-side, so the host app registers
a backend through a small C entry point and Swift forwards to it. Callers never learn which
platform they are on.

> **Status: pre-1.0.** The API is small and the behavioural contract is covered by a test suite
> that runs against every backend, but the API may still evolve before `1.0.0`. Breaking changes
> are called out in the [CHANGELOG](CHANGELOG.md).

## Why

If you share business logic between an iOS app and an Android app written in Swift, credential
storage is one of the first things that stops compiling. `Security` does not exist off Apple, and
the Android equivalent — Keystore, usually via `EncryptedSharedPreferences` — is a Java API with
no Swift bindings.

SecureStore solves that without dragging a Java-interop layer into your Swift code:

- **One protocol, a handful of operations.** `set`, `data(for:)`, `remove`, `removeAll`,
  `keys(withPrefix:)` — the surface a token store actually needs, and nothing else. `allKeys()`
  comes free as an empty prefix.
- **Prefix enumeration, so one item per credential is practical.** Store
  `"session.<accountID>"` per account and enumerate with `keys(withPrefix: "session.")`, rather
  than packing everything into a single blob and re-encoding it on every write.
- **No Apple concepts in the cross-platform API.** There is no `accessGroup` parameter. Sharing
  scope is an opaque `namespace` string, because Android has no App-Group equivalent and baking
  one platform's model into the API would defeat the purpose.
- **Errors are errors.** Every operation throws, including reads. A credential that is missing
  because the item was locked is a very different situation from one that was never written, and
  the API refuses to conflate them.
- **A failure says what actually happened.** `SecureStoreError.platform` carries a
  `PlatformFailure` with the backend, the operation, the platform's own code, its message, and
  its error domain — so `error.localizedDescription` gives you something like *"Secret Service
  set failed (g-io-error-quark, code 19): Object does not exist at path
  /org/freedesktop/secrets/collection/login"* rather than a bare number you have to go look up.
  (`print(error)` shows the same text wrapped in the case name, `platform(…)`.)
- **The host owns the Android implementation.** Swift never links a Java SDK; you register C
  callbacks once at startup.

## Installation

```swift
.package(url: "https://github.com/AlexNachbaur/securestore-swift.git", from: "0.2.0")
```

```swift
.target(name: "YourTarget", dependencies: [
    .product(name: "SecureStore", package: "securestore-swift")
])
```

## Usage

```swift
import SecureStore

let store = PlatformSecureStore(service: "com.example.auth")

try store.set(Data(token.utf8), for: "session")

if let data = try store.data(for: "session") {
    let token = String(decoding: data, as: UTF8.self)
}

try store.remove("session")
```

`PlatformSecureStore` is a typealias for whichever backend the platform you are compiling for
has — `KeychainSecureStore` on Apple, `WindowsSecureStore` on Windows, `LinuxSecureStore` on
Linux, `HostSecureStore` everywhere else — so shared code never has to spell out the `#if`
itself. To stay platform-agnostic, depend on the protocol and construct the concrete store once:

```swift
func makeStore(service: String) -> any SecureStore {
    PlatformSecureStore(service: service)
}
```

Exactly one backend type exists per platform, so there is no runtime selection and nothing to
configure. The concrete names remain available for code that is platform-specific anyway and
wants to say so.

### Calls block

Every operation is synchronous and takes as long as the platform does. That is normally
microseconds, but a locked Linux keyring raises an unlock prompt and the call does not return
until the user answers it; a macOS keychain can prompt too, and a host backend is as fast as the
host made it. There is no timeout and no cancellation, so keep store calls off the main actor:

```swift
let token = try await Task.detached { try store.data(for: "session") }.value
```

### Sharing between processes

`namespace` scopes items beyond a single process. On Apple it maps to a keychain access group,
letting an app and its extensions read the same items:

```swift
KeychainSecureStore(service: "com.example.auth", namespace: "TEAMID.com.example.shared")
```

Hosts with no equivalent concept ignore it. Design your key layout so that a host which cannot
share is still correct — just less convenient.

**On macOS, `namespace` is ignored by default.** macOS has two keychains. The default is the
file-based login keychain, which disregards the access group and the accessibility class: two
stores that differ only in `namespace` read and overwrite each other's items there. The *data
protection* keychain — the only one iOS has — enforces both, and is opt-in:

```swift
KeychainSecureStore(
    service: "com.example.auth",
    namespace: "TEAMID.com.example.shared",
    usesDataProtectionKeychain: true
)
```

It is not the default because it needs a keychain entitlement: a signed app (or a tool with
`keychain-access-groups`) has one, while `swift run`, `swift test`, and unsigned command-line
tools do not and get `errSecMissingEntitlement` (-34018) on every call — thrown, never a silent
fallback. The two keychains do not share items, so turning the flag on for a shipped macOS app
means migrating: read from a store without it, write to one with it. The flag changes nothing
on iOS, tvOS, watchOS, or visionOS.

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
    int32_t (*keys)(const char *service, const char *namespace_, const char *prefix,
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
   `SecureStoreError.platform(PlatformFailure)` carrying the host's own code, so a failure in the
   field can be traced to a specific platform error rather than a generic one:

   ```swift
   do {
       try store.set(token, for: "session")
   } catch let SecureStoreError.platform(failure) {
       log("\(failure)")        // "host backend set failed (code 42): ..."
       report(code: failure.code)
   }
   ```

   Register a describer (below) and `failure.message` carries your own text instead of `nil`.

Until a host registers, every operation throws `SecureStoreError.backendNotRegistered`. That is
deliberate: a store that silently appears to work while persisting nothing is far worse than a
loud failure.

A host may **optionally** register a describer, so its status codes reach callers as text
instead of bare numbers — the same quality of error the native backends give:

```c
void securestore_register_host_describer(
    void (*describe)(int32_t status,
                     void *context,
                     void (*sink)(void *context, const char *message)));
```

It is a separate entry point rather than an extra parameter on `securestore_register_host`,
so a host compiled before it existed keeps working untouched.

Three details of the ABI that the signatures do not show, and that a JNI shim has to get right:

- **Strings are standard UTF-8**, in both directions. JNI's `NewStringUTF` and
  `GetStringUTFChars` speak *Modified* UTF-8, which differs for any character outside the Basic
  Multilingual Plane — convert through `byte[]` and `StandardCharsets.UTF_8` instead.
- **Callbacks arrive on whichever thread called the store**, which may not be attached to the
  JVM. Attach it before touching a `JNIEnv`.
- **No function pointer may be `NULL`.** Only `namespace_` can be.

See [docs/design/host-bridge-abi.md](docs/design/host-bridge-abi.md) for the full contract, and
[docs/design/securestore_host.h](docs/design/securestore_host.h) for a C header declaring both
entry points that you can copy into a shim.

## Requirements

| Platform | Backend |
|---|---|
| iOS 13+ / macOS 10.15+ / watchOS 7+ / tvOS 13+ / visionOS 1+ | `KeychainSecureStore` — Keychain Services |
| Windows | `WindowsSecureStore` — Credential Manager (`CredWriteW` and friends) |
| Linux | `LinuxSecureStore` — freedesktop.org Secret Service, via libsecret |
| Android | `HostSecureStore` — host-registered callbacks |

Swift 6.3+. Android builds use the official [Swift SDK for Android](https://www.swift.org/documentation/articles/swift-sdk-for-android-getting-started.html).

Two platform-specific notes worth knowing before you depend on this:

- **Linux needs libsecret at build time.** Install `libsecret-1-dev` (Debian/Ubuntu) or
  `libsecret-devel` (Fedora/RHEL); it is reached through pkg-config. The dependency is scoped to
  Linux, so no other platform requires it. At *run* time a Secret Service provider must be
  present — gnome-keyring, KWallet's Secret Service bridge, or KeePassXC. A headless host with
  none of them will fail loudly on first use rather than silently persisting nothing.
- **Windows caps a credential at 2,560 bytes** (`CRED_MAX_CREDENTIAL_BLOB_SIZE`), far below
  what Keychain Services allows. Exceeding it fails with a platform error rather than
  truncating, but it is a real portability limit if you were treating a secure store as
  general-purpose storage.

## Testing

The behavioural contract is written once and run against whichever backend the platform provides,
so the four backends cannot drift:

```bash
swift test                                               # the platform you are on
swift build --build-tests \
    --swift-sdk aarch64-unknown-linux-android28          # Android: cross-compiles the suite
```

`swift test` runs against the real store — the Keychain on macOS, Credential Manager on Windows,
a Secret Service provider on Linux — scoped to a unique service per run and emptied afterwards.
The Android line only cross-compiles: the resulting test binary has to be pushed to an emulator
or device to run, which is what CI does on every change, against an in-memory host registered
through the real C entry point.

That suite already earned its keep: it caught that `SecItemDelete` deletes *one* matching item on
the macOS legacy keychain but *all* of them on iOS — a `removeAll` that silently left items
behind on one Apple platform and not another.

## License

MIT — see [LICENSE](LICENSE).

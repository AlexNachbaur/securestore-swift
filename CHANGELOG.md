# Changelog

All notable changes to SecureStore will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`WindowsSecureStore`** — a native Windows backend over Credential Manager
  (`CredWriteW`/`CredReadW`/`CredDeleteW`/`CredEnumerateW`), storing `CRED_TYPE_GENERIC`
  credentials with `CRED_PERSIST_LOCAL_MACHINE`. Roaming persistence is deliberately not used:
  an application's own tokens should not replicate to machines the user never authorised.
  `keys(withPrefix:)` pushes the prefix into `CredEnumerateW`'s native filter.
- **`LinuxSecureStore`** — a native Linux backend over the freedesktop.org Secret Service, via
  libsecret. Items land in the user's default collection and searches unlock it on demand, so a
  locked keyring prompts rather than reading as empty.
- **`CSecret`** — a `.systemLibrary` target wrapping `<libsecret/secret.h>` through pkg-config.
- **`PlatformFailure`** — the payload of `SecureStoreError.platform`, carrying the backend, the
  operation, the platform's own code, its message, and its error domain, with a
  `CustomStringConvertible` that renders all of it on one line. Every backend now resolves the
  platform's text: `SecCopyErrorMessageString` on Apple, `FormatMessageW` on Windows, the
  `GError` message and domain on Linux.
- **`securestore_register_host_describer`** — an optional C entry point letting an Android host
  translate its own status codes into messages, through the same sink convention the rest of
  the ABI uses. Deliberately a **new symbol** rather than a parameter on
  `securestore_register_host`: adding a parameter would change an existing signature and break
  every host already compiled against it. A host that never calls it is unaffected.

### Changed

- **⚠️ `SecureStoreError.platform` changed shape**, from `case platform(code: Int32)` to
  `case platform(PlatformFailure)`. Existing `catch SecureStoreError.platform(let code)` sites
  become `catch let SecureStoreError.platform(failure)`, with the code at `failure.code`. The
  old case could not answer which store failed or what was being attempted, and discarded any
  message the platform supplied — which is how a container with no Secret Service collection
  presented as `.platform(code: 19)` on writes while reads of absent keys succeeded, reading as
  a backend bug rather than the environment problem it was.
- **The host bridge is now Android-only.** `HostSecureStore`, `SecureStoreHostCallbacks`,
  `registerSecureStoreHost` and the `securestore_register_host` C entry point were gated
  `#if !canImport(Security)`, so they compiled on Windows and Linux; they are now
  `#if !canImport(Security) && !os(Windows) && !os(Linux)`. **This removes API on those two
  platforms.** A Windows or Linux host that was registering its own backend must switch to the
  native store, which needs no registration at all. Backend selection stays compile-time and
  the four gates remain mutually exclusive and exhaustive.
- The contract suite gained Windows and Linux branches, so all four backends are asserted by
  one body of tests rather than two.
- CI now builds and tests on **macOS, Linux, Windows, and an Android emulator**, and *builds*
  on an iOS simulator. The Linux job installs `libsecret-1-dev` and runs gnome-keyring under
  `dbus-run-session`, so the suite exercises a real Secret Service rather than a stub.
  - The iOS job is build-only, deliberately. A SwiftPM test bundle has no host application, so
    the simulator grants it no keychain entitlement and every Keychain Services call fails with
    `-34018` (`errSecMissingEntitlement`); supplying `CODE_SIGN_ENTITLEMENTS` with ad-hoc
    signing does not work around it. Running the contract suite on iOS would require checking
    an `.xcodeproj` with a host app target into a pure-SwiftPM package. macOS remains the job
    that asserts Keychain behaviour.
- The lint job gates every other job. Unlike the sibling repositories, the platform jobs then
  fan out in parallel rather than chaining behind Linux: each platform here runs a *different
  backend*, so a Linux failure predicts nothing about Windows, and chaining serialised the
  discovery of unrelated bugs across separate CI rounds.
- Dependabot now watches the `github-actions` ecosystem. The `swift` ecosystem was removed: the
  package has no SwiftPM dependencies, so it had nothing to do and read as coverage that did not
  exist.
- Actions moved to current majors (`checkout` v6 → v7, `cache` v4 → v6).

### Note on the dependency policy

The package was previously dependency-free by policy. It now has exactly one dependency,
libsecret, scoped to Linux by `.when(platforms: [.linux])` — no other platform requires
`libsecret-1-dev` to build. This was an explicit decision, not drift; the policy is otherwise
unchanged.

## [0.1.0] - 2026-07-26

Initial release.

### Added

- **`SecureStore` protocol** — five required operations over the OS secure store: `set(_:for:)`,
  `data(for:)`, `remove(_:)`, `removeAll()`, `keys(withPrefix:)`, with `allKeys()` provided as an
  extension over the last. Every operation throws, including reads, so a locked or unreadable item
  is never silently indistinguishable from an absent one.
- **Prefix enumeration** — `keys(withPrefix:)` makes one-item-per-credential practical: store
  `"session.<accountID>"` per account and enumerate with `keys(withPrefix: "session.")` instead of
  packing every account into a single blob. Prefix is the primitive because it is what the
  platforms actually offer — Windows Credential Manager's `CredEnumerateW` filter is documented as
  "a name prefix followed by an asterisk" and supports nothing richer, so anything more expressive
  would have to be emulated everywhere. Apple filters in-process (Keychain Services has no prefix
  predicate for generic-password accounts); hosts receive the prefix and are expected to push it
  down.
- **`KeychainSecureStore`** — Apple backend over Keychain Services, using
  `kSecClassGenericPassword` keyed by service + account, with
  `kSecAttrAccessibleAfterFirstUnlock` so credentials stay readable to background and extension
  processes on a locked device.
- **`HostSecureStore`** — backend for platforms with no Swift-native secure store (Android's
  Keystore). The host registers C callbacks through `securestore_register_host`; Swift forwards
  to them and never links a Java SDK. See
  [docs/design/host-bridge-abi.md](docs/design/host-bridge-abi.md).
- **`SecureStoreConfiguration`** with an opaque `namespace` rather than an `accessGroup`. On Apple
  it maps to a keychain access group; hosts without an equivalent ignore it. Naming it after the
  Apple concept would have baked one platform's model into a cross-platform API.
- **Backend-agnostic contract suite** — the behavioural contract is written once and run against
  whichever backend the platform provides, so Apple and Android cannot drift. On non-Apple
  platforms it registers an in-memory host through the real C entry point, exercising the ABI
  itself rather than a Swift stand-in.

### Platform behaviour worth knowing

Two divergences the implementation accounts for, both found by the contract suite during
development rather than by reading documentation. Recorded here because anyone writing a backend —
or debugging one — will otherwise trip over them.

- **`SecItemDelete` is not uniform across Apple platforms.** A query matching several items deletes
  all of them on iOS, but exactly one on the macOS legacy keychain. `removeAll()` therefore loops
  until the store reports nothing left instead of assuming the iOS semantics.
- **A zero-length value is a value.** The host bridge's data sink is invoked only for an item that
  exists — a missing item is reported by the status code and never calls back — so a zero-length
  callback means "stored, and empty" and yields an empty `Data`, not `nil`. Treating it as `nil`
  would make an empty credential indistinguishable from an absent one, which is exactly what this
  package refuses to do. Caught by the Android emulator run; the Apple backend was already correct,
  so no amount of Apple-side testing would have surfaced it.

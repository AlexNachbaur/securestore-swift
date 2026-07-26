# Changelog

All notable changes to SecureStore will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

### Fixed

- `HostSecureStore.data(for:)` returned `nil` for a stored-but-empty value, making it
  indistinguishable from a missing one — the exact conflation this package exists to prevent. The
  data sink now treats a zero-length callback as an empty value, since the sink is only invoked
  for an item that exists. Caught by the contract suite running in an Android emulator, not on
  Apple, where the Keychain backend already behaved correctly.
- `removeAll()` deleted only a single item on the macOS legacy keychain. `SecItemDelete` removes
  every matching item on iOS but exactly one on macOS; the implementation now loops until the
  store reports nothing left. Caught by the shared contract suite on its first run.

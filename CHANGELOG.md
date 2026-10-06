# Changelog

All notable changes to SecureStore will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Fixes from the October 2026 audit. Finding IDs (`SS-n`) refer to that audit.

### Added

- **`KeychainSecureStore(…, usesDataProtectionKeychain:)`** — opts a store into the data
  protection keychain on macOS. The audit confirmed what Apple's TN3137 describes: the macOS
  file-based keychain, the default there, ignores the access group and the accessibility class.
  An item written with one `namespace` read back under another and under none, and no
  accessibility attribute was stored — so on macOS two stores differing only in `namespace`
  were the same store, which is exactly the "readable outside its intended scope" case
  SECURITY.md lists as in scope. The data protection keychain enforces both.

  It is opt-in rather than the new default because that keychain requires a keychain
  entitlement: an unsigned process (`swift test`, `swift run`, a plain command-line tool) gets
  `errSecMissingEntitlement` on every call, so flipping the default would break every such
  consumer. With the flag set and no entitlement the store throws that failure — it never falls
  back to the file-based keychain. The two keychains hold separate items, so enabling it on a
  shipped app is a migration. No effect off macOS. The flag lives on the Keychain backend, not
  on `SecureStoreConfiguration`, because it is an Apple concept. (SS-1)
- **`PlatformSecureStore`** — a typealias for whichever backend the platform being compiled for
  has: `KeychainSecureStore`, `WindowsSecureStore`, `LinuxSecureStore`, or `HostSecureStore`.
  The package's premise is that callers never learn which platform they are on, yet every
  consumer had to write the same four-branch `#if` to construct a store. Each backend file
  defines the alias inside its own existing gate, so it cannot disagree with backend selection.
  The concrete names are unchanged. (SS-21)
- **`SecureStoreError` and `PlatformFailure` conform to `LocalizedError`.** Without it,
  `error.localizedDescription` — what most logging and alert code actually calls — returned
  Foundation's "The operation couldn’t be completed", discarding the backend, operation, code
  and message that `PlatformFailure` exists to carry. It now returns the same line as
  `description`. (SS-20)
- **`docs/design/securestore_host.h`** — a reference C header declaring
  `securestore_register_host` and `securestore_register_host_describer`, for a JNI shim to
  copy. It is documentation only: no target includes it, so it cannot affect the build. (SS-10)

### Fixed

- **Host bridge: a `get` that returns OK without calling the sink now throws
  `SecureStoreError.invalidData`** instead of returning `nil`. A host that failed inside its own
  lookup and still returned `0`, or simply forgot to call back, read as "no such item" — a
  signed-out user, from the one backend written by third parties. A missing item is still
  reported by status `1` and still reads as `nil`. **A host relying on "OK and no callback" to
  mean absent must return `1` instead.** (SS-3)
- **Host bridge: a malformed sink call now throws `SecureStoreError.invalidData`** instead of
  yielding an empty value: a negative length, or a `NULL` buffer with a positive length. Both
  describe no value at all, and reporting them as "stored, and empty" turned a host bug into a
  plausible credential. The Windows and Linux backends already refused the equivalent. (SS-24)
- **Host bridge: storing a value larger than `Int32.max` bytes throws instead of trapping.** The
  C signature carries the length as `int32_t` and `Int32(_:)` traps on overflow, so an
  oversized value crashed the process; the Windows backend had the equivalent guard and the
  host path did not. The failure is a `PlatformFailure` for the host backend with code `0` —
  the host was never called, and `0` is the one code a host cannot report as a failure. (SS-4)
- **Windows: a key beginning with a combining mark is no longer lost.** Such a key fuses with
  the `:` that ends the store's target-name prefix into a single user-perceived character, so
  the character-based `hasPrefix` concluded the credential belonged to another store: it was
  missing from `keys()`, and `removeAll()` left it behind in the user's Credential Manager. The
  store's prefix is now matched by Unicode scalar. (SS-5)
- **Windows: `%` and `:` are now escaped even when followed by a combining mark.** The escape
  used Foundation's default search, which matches whole composed characters and so skipped a
  separator that had a combining mark after it, leaving it raw in the target name. Two stores
  could then flatten to the same name — namespace `"b:\u{301}c"` + key `"\u{301}k"` and
  namespace `"b"` + key `"\u{301}c:\u{301}k"` — which is exactly the collision the escaping
  exists to prevent. Found while verifying SS-5; the search is now literal. **A credential
  written by 0.2.0 under such a name is not found by this version**; ordinary names are
  unaffected.
- **Windows: `GetLastError` is captured once, in the same expression as the call that failed.**
  It was read after the enclosing `withCString` scope had unwound, and then a second time to
  build the error — so the `ERROR_NOT_FOUND` check and the reported code could each see a value
  some later call had overwritten, turning a missing item into a thrown error or the reverse.
  (SS-7)
- **Linux: reading a locked item reports that it is locked.** When an unlock prompt is
  dismissed, libsecret returns the item with no secret and no `GError`, which surfaced as
  `.invalidData` — sending the caller to look for corrupt bytes, or to delete a perfectly good
  credential. It is now a `PlatformFailure` carrying libsecret's own `SECRET_ERROR_IS_LOCKED`
  (domain `secret-error`, code 2). (SS-8)
- **Apple: `set` no longer fails when another process deletes the item mid-write.** A write is
  an add that falls back to an update on duplicate; a delete landing between the two made the
  update fail with `errSecItemNotFound`, from a store with nothing wrong with it. The add is now
  retried once. An app and its extensions share a store, so this is an ordinary interleaving
  rather than a theoretical one. (SS-14)

### Changed

- `PlatformFailure.Operation.removeAll` no longer spells out a raw value identical to its case
  name. The value is unchanged. (SS-20)

### Documentation

- **Every operation is synchronous and can block on UI** — a Linux keyring unlock prompt, a
  macOS keychain prompt, or whatever a host backend does — with no timeout and no cancellation.
  This was true and unstated; it is now on the protocol, on `LinuxSecureStore`, and in the
  README, with the advice to keep store calls off the main actor. (SS-9)
- **The host ABI now specifies what the signatures do not** (`docs/design/host-bridge-abi.md`,
  Rules 5–7): strings are standard UTF-8 and therefore *not* what JNI's `NewStringUTF` /
  `GetStringUTFChars` produce; callbacks run synchronously on the calling Swift thread, which
  may not be attached to the JVM; and which pointers may be `NULL` — no function pointer may,
  and passing one is undefined behaviour because the `@_cdecl` parameters are non-optional.
  (SS-10)
- The ABI document no longer claims a host can be validated "by running the same tests". The
  contract suite always installs its own in-memory fixture and cannot be pointed at a real
  host. (SS-12)
- **`SECURITY.md` now states what the platform stores do not protect**: on Windows, and on Linux
  once the keyring is unlocked, any process running as the same user can read the items; and
  service, namespace and key names are stored unencrypted on both. `service`/`namespace` are a
  collision boundary there, not an access-control one. The supported-versions table also said
  `0.1.x`. (SS-24, SS-17)
- Doc comments added to every public initialiser, the `PlatformFailure` members and enum cases,
  and the `SecureStoreHostCallbacks` members. (SS-22)
- Corrected stale statements: the protocol's summary still described two backends; the README
  showed `print(error)` output without the `platform(…)` wrapper it prints, pointed "above" at
  a section below, and described a cross-compile command as running in an emulator; the ABI
  document counted six operations where there are five. `Package.swift` claimed pkg-config is
  "never consulted" off Linux, though SwiftPM looks for the file everywhere and warns
  `couldn't find pc file for libsecret-1` — harmless, and now explained. (SS-17, SS-19)

### Tests

- The contract suite gained keys that are awkward for at least one backend — containing `:`,
  `%`, `*`, the escape sequences themselves, non-ASCII, and combining marks — plus literal
  prefix matching for the same characters and a service/key separator collision. (SS-15, SS-5)
- **Namespace isolation is now asserted** on Windows, Linux, and the host bridge: same service,
  different namespaces, including that an unscoped store does not reach into a scoped one. It
  is deliberately *not* asserted on Apple, where the namespace is a keychain access group that
  a `swift test` process has no entitlement for. (SS-2)
- New suites for a misbehaving host (SS-3, SS-4, SS-24) and for the Keychain add-or-update
  interleaving (SS-14). The forced-failure tests moved out of the `SecureStoreConfiguration`
  suite, where a failure blamed the wrong thing. (SS-15)

## [0.2.0] - 2026-07-27

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

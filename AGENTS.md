# AGENTS.md

Instructions for AI agents working in the securestore-swift repository itself. If you are
*integrating* SecureStore into another project, read [llms.txt](llms.txt) and the
[README](README.md) instead.

## What this package is

A cross-platform secure-credential store: one `SecureStore` protocol (set, read, remove,
removeAll, `keys(withPrefix:)`) and four backends, selected at compile time — Keychain Services
on Apple, Credential Manager on Windows, the freedesktop.org Secret Service on Linux, and a
host-registered C bridge for platforms with no Swift-reachable store (Android). Callers never
learn which platform they are on. It exists so shared Swift business logic — the kind that
compiles for both iOS and Android — can persist credentials without dragging a Java-interop
layer into it. Swift 6.3+, one library target plus the `CSecret` system-library shim.

The only external dependency is libsecret, and it is scoped to Linux by a
`.when(platforms: [.linux])` condition on the target dependency — that condition is load-bearing,
because without it `libsecret-1-dev` becomes a build requirement on every platform. This package
is linked into credential paths on multiple platforms; do not add another dependency, or widen
that condition, without raising it first.

## Making decisions

- **Never assume or default to the easiest solution.** When there is a real choice — an
  architectural direction, a public-API or C-ABI shape, a behavior the contract suite
  deliberately asserts — stop and ask first.
- Present the options with trade-offs and a recommendation; the maintainer has the final say.
- Do not silently pick an approach, even when one seems obvious.
- Decisions already recorded below are settled: build on them rather than re-asking.

## Non-negotiable design rules

These are properties, not preferences. A change that breaks one is wrong even if it compiles and
passes.

1. **No platform concepts in the cross-platform API.** `namespace` is not `accessGroup`. If you
   cannot express something without an Apple (or Android, or Windows) term, it belongs in a
   backend, not the protocol. A leaked platform concept defeats the purpose of the package.
2. **Reads throw; absent and unreadable are different.** A missing item is `nil`; anything else
   throws. Never collapse a failure into `nil` — a locked keychain must not look like a
   signed-out user, which is the exact bug this package exists to prevent. Never add a
   "convenience" that erases the distinction.
3. **A thrown failure must be actionable on its own.** `SecureStoreError.platform` wraps a
   `PlatformFailure` (backend, operation, code, message, domain), because a bare code names
   neither the store that produced it nor what was being attempted, and the same number means
   different things per platform. Every backend resolves the platform's own text
   (`SecCopyErrorMessageString`, `FormatMessageW`, the `GError` message, the host's describer);
   a new backend that does not is incomplete. This is not polish: `.platform(code: 19)` cost a
   full CI round to diagnose when libsecret had been reporting the exact cause all along.
4. **Fail loud when unconfigured.** On a host-registered platform, operations throw
   `backendNotRegistered` until the host registers. A store that appears to work while
   persisting nothing surfaces days later as data loss.
5. **No heap pointers cross the C boundary.** Results come back through sink callbacks that copy
   within the call's lifetime; each side frees only what it allocated. Never return a malloc'd
   buffer for the other side to free. This is a memory-safety property, not a style choice.
6. **Every C operation returns a status.** `0` ok, `1` not found, anything else a host error
   surfaced verbatim in `SecureStoreError.platform`. A host may additionally register a
   describer (`securestore_register_host_describer`) to turn its codes into text.
7. **Callbacks are non-capturing `@convention(c)`.** Per-call state travels through the explicit
   `context` pointer. That is what makes them trivially `Sendable` and safe to hand to JNI.
8. **The C ABI is a compatibility surface.** Additive callbacks are fine; changing an existing
   signature breaks every host compiled against it and is a semver-major change. Full contract
   in [docs/design/host-bridge-abi.md](docs/design/host-bridge-abi.md).
9. **Never `try?` or `try!`.** Not in production, not in tests, not in `defer`, not in
   throwaway cleanup. It discards the error, which is the failure-swallowing this package
   exists to prevent. Use `do { try … } catch { … }`, or mark the function `throws` and
   propagate. `defer` cannot throw, so cleanup records a test issue instead of discarding — see
   `cleanUp` in the contract suite.

## Architecture (settled decisions — do not relitigate)

- **Toolchain**: Swift 6.3 (`swift-tools-version: 6.3`). CI must therefore use
  macos-26/Xcode 26.x and the `swift:6.3` container — Swift 6.1 cannot parse the manifest.
- **Module layout**: one library target, `SecureStore`, plus the `CSecret` system-library shim.
  - `SecureStore.swift` — protocol, `SecureStoreConfiguration`, `SecureStoreError`. Portable.
  - `KeychainSecureStore.swift` — Apple backend, `#if canImport(Security)`.
  - `WindowsSecureStore.swift` — Credential Manager backend, `#if os(Windows)`.
  - `LinuxSecureStore.swift` — Secret Service backend via libsecret, `#if os(Linux)`.
  - `HostSecureStore.swift` — host-registered backend plus the `@_cdecl` entry points,
    `#if !canImport(Security) && !os(Windows) && !os(Linux)`. Android and anything else with no
    Swift-reachable store.
- **Backend selection is compile-time.** There is exactly one correct backend per platform,
  and the four `#if` gates are mutually exclusive and exhaustive. Never add a runtime fallback
  chain — which backend you get must be a property of the build, not of what happened to be
  installed.
- **Windows flattens; the others do not.** Credential Manager identifies an item by a single
  `TargetName`, so service/namespace/key are escaped (`%` and `:`) and joined. The escape is
  per-character specifically so it stays prefix-preserving and `keys(withPrefix:)` can push the
  filter into `CredEnumerateW`. Keychain and the Secret Service match on attribute sets and
  need none of this.
- **The Linux backend passes a NULL `SecretSchema`** and sets `xdg:schema` by hand.
  Constructing a `SecretSchema` from Swift means populating a 32-element fixed C array imported
  as a tuple, which buys type-checking of attributes that are all strings anyway.
- **Android integration is host-out, not Swift-in.** Swift calls C callbacks the host installs.
  It does **not** bind the Java SDK, and `swift-java`/`jextract` is deliberately not on the
  critical path.
- **`namespace` is opaque.** On Apple it maps to a keychain access group; hosts without an
  equivalent ignore it rather than failing.
- **The data protection keychain is opt-in on macOS** (`usesDataProtectionKeychain`, on
  `KeychainSecureStore` only — it is an Apple concept and stays out of
  `SecureStoreConfiguration`). The macOS file-based keychain ignores the access group and
  accessibility class, but the data protection keychain needs an entitlement that `swift test`
  and unsigned tools lack, so it cannot be the default. With the flag set and no entitlement
  writes throw `errSecMissingEntitlement` and reads see an empty keychain (Security answers
  them with "not found", not an error); it must never fall back.
- **The registry is `Mutex`-guarded and not shared across capabilities.** Registration lands
  on the host's startup thread while operations arrive from arbitrary concurrency contexts. It
  is ~20 lines, and callback signatures differ enough between domains that a shared abstraction
  would leak; the reusable part is the *conventions*, which live in the ABI document.

## Where behaviour is tested

`Tests/SecureStoreTests/SecureStoreContractTests.swift` is **not** platform-guarded, on purpose:
it runs against the real Keychain on Apple, the real Credential Manager on Windows, a real
Secret Service provider on Linux, and a host-registered in-memory backend on Android, so the
backends cannot drift. Put behavioural assertions there, not in a backend-specific file. Adding
a backend without adding a branch to `makeStore` leaves it unasserted — the one thing the suite
exists to prevent.

`HostBackendFixture.swift` registers that in-memory backend through the *real* `@_cdecl` entry
point, so the suite exercises the actual ABI rather than a Swift stand-in. Keep it that way — a
fixture that bypasses the C boundary would test nothing that matters.

Tests must scope themselves to a unique service per run, so a failure cannot leave residue in a
developer's real keychain and concurrent runs cannot collide.

Trust tests over documentation for platform APIs: `SecItemDelete` removes every matching item
on iOS but exactly one on the macOS legacy keychain, which is why `removeAll()` loops —
discovered by running the suite, not by reading the docs. Assume other such differences exist.

CI runs macOS, an iOS simulator (build only — a SwiftPM test bundle has no keychain
entitlement there), Linux, Windows, and an Android emulator. The Linux job installs
`libsecret-1-dev` and starts gnome-keyring under `dbus-run-session`, so the suite runs against
a real Secret Service rather than a stub. Only the backend for the platform you are on compiles
locally: an edit to another backend is unverified until CI has run it, so keep such edits small
and say so in the PR.

## Code style (enforced)

- swift-format with the checked-in `.swift-format`: 120 columns, 4-space indent.
- No force unwraps anywhere (tests use `try #require(...)`); no `DispatchQueue` — Swift
  concurrency only; prefer value types.
- Never use caseless enums as namespaces; use a struct with static members.
- Swift Testing (`import Testing`), never XCTest.
- Documentation comments on all public API, explaining *why* where the reason is non-obvious.

## Before you finish

```bash
make format   # swift format --in-place --recursive Sources Tests Package.swift
make check    # lint, build, test — must pass before any commit
swift build --swift-sdk aarch64-unknown-linux-android28   # if the SDK is installed
```

Update [CHANGELOG.md](CHANGELOG.md) under `[Unreleased]` for anything user-visible, and say *why*
a change was made — the existing entries are written to be read a year later by someone deciding
whether a behaviour is intentional.

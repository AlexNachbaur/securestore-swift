# CLAUDE.md — SecureStore Cross-Platform Credential Storage

## Decision-Making Rules

- **Never assume or default to the easiest solution.** When there are choices, options, or architectural decisions to make, stop and ask first.
- Present options with pros/cons and a recommendation, but the user has the ultimate say.
- Ask clarifying questions before proceeding when requirements are ambiguous or multiple valid approaches exist.
- Do not silently pick an approach — even if one seems obvious.
- Decisions already made (see "Decided Architecture" below) do not need re-asking — build on them.

## Project Summary

One secure-credential API for Swift across Apple platforms and Android. A single `SecureStore` protocol covers the operations a token store actually needs — set, read, remove, removeAll, and prefix-scoped key enumeration; Apple platforms are served by Keychain Services directly, and platforms whose secure store lives outside Swift (Android's Keystore, reached via Java) are served by a backend the host registers through a small C entry point. Callers never learn which platform they are on. Built to let shared Swift business logic — the kind that compiles for both iOS and Android — persist credentials without dragging a Java-interop layer into it.

## Design Principles

1. **The cross-platform API must not name platform concepts.** `namespace` is not `accessGroup`. If something cannot be expressed without an Apple (or Android) term, it belongs in a backend, not the protocol. A leaked platform concept defeats the entire purpose of the package.
2. **Reads throw; absent and unreadable are different.** A missing item is `nil`, anything else throws. Collapsing a failure into `nil` turns a locked keychain into a mysteriously signed-out user — the exact bug this package exists to prevent. Never add "convenience" that erases the distinction.
2a. **A thrown failure must be actionable on its own.** `SecureStoreError.platform` carries a `PlatformFailure` — backend, operation, code, message, domain — because a bare code names neither the store that produced it nor what was being attempted, and the same number means different things per platform. Every backend resolves the platform's own text (`SecCopyErrorMessageString`, `FormatMessageW`, the `GError` message, the host's describer); a new backend that does not is incomplete. This is not polish: `.platform(code: 19)` cost a full CI round to diagnose when libsecret had been reporting the exact cause all along.
3. **Fail loud when unconfigured.** On a host-registered platform, operations throw `backendNotRegistered` until the host registers. A store that appears to work while persisting nothing is far worse than an obvious failure, because it surfaces days later as data loss.
4. **The C bridge never transfers pointer ownership.** Results come back through sink callbacks that copy within the call; each side frees only what it allocated. This is a memory-safety property, not a style choice.
5. **Behaviour is asserted once, for every backend.** The contract suite is not platform-guarded, so Apple and Android cannot drift. Backend-specific tests cover backend-specific mechanics only.
6. **Trust tests over documentation for platform APIs.** `SecItemDelete` removes every matching item on iOS but exactly one on the macOS legacy keychain — discovered by running the suite, not by reading the docs. Assume more such divergence exists.

## Decided Architecture

These decisions were made with the project owner and are settled:

- **License/distribution**: MIT, open source at `github.com/AlexNachbaur/securestore-swift`.
- **Toolchain**: Swift 6.3 (`swift-tools-version: 6.3`). CI must therefore use macos-26/Xcode 26.x and the `swift:6.3` container — Swift 6.1 cannot parse the manifest.
- **Dependency policy**: **one, scoped to one platform** — libsecret, via the `CSecret` system-library target, used only by the Linux backend. Nothing else. This package is linked into credential paths on multiple platforms; do not add another dependency without asking. The `.when(platforms: [.linux])` condition on the target dependency is load-bearing: it is what keeps `libsecret-1-dev` from becoming a build requirement everywhere else.
- **Module layout**: one library target, `SecureStore`, plus the `CSecret` system-library shim.
  - `SecureStore.swift` — protocol, `SecureStoreConfiguration`, `SecureStoreError`. Portable.
  - `KeychainSecureStore.swift` — Apple backend, `#if canImport(Security)`.
  - `WindowsSecureStore.swift` — Credential Manager backend, `#if os(Windows)`.
  - `LinuxSecureStore.swift` — Secret Service backend via libsecret, `#if os(Linux)`.
  - `HostSecureStore.swift` — host-registered backend + the `@_cdecl` entry point, `#if !canImport(Security) && !os(Windows) && !os(Linux)`. Android and anything else with no Swift-reachable store.
- **Backend selection is compile-time**; there is exactly one correct backend per platform, and the four `#if` gates are mutually exclusive and exhaustive. Never add a runtime fallback chain — which backend you get must be a property of the build, not of what happened to be installed.
- **Windows flattens; the others do not.** Credential Manager identifies an item by a single `TargetName`, so service/namespace/key are escaped (`%` and `:`) and joined. The escape is per-character specifically so it stays prefix-preserving and `keys(withPrefix:)` can push the filter into `CredEnumerateW`. Keychain and the Secret Service both match on attribute sets and need none of this.
- **The Linux backend passes a NULL `SecretSchema`** and sets `xdg:schema` by hand. Constructing a `SecretSchema` from Swift means populating a 32-element fixed C array imported as a tuple, which buys type-checking of attributes that are all strings anyway.
- **Android integration is host-out, not Swift-in**: Swift calls C callbacks the host installs. It does **not** bind the Java SDK, and `swift-java`/`jextract` is deliberately not on the critical path.
- **The C ABI is a compatibility surface.** Additive callbacks are fine; changing an existing signature breaks every host compiled against it and is semver-major. Full contract in `docs/design/host-bridge-abi.md`.
- **`namespace` is opaque.** On Apple it maps to a keychain access group; hosts without an equivalent ignore it rather than failing.

## Testing Rules

- Swift Testing (`import Testing`), not XCTest.
- **Behavioural assertions go in `Tests/SecureStoreTests/SecureStoreContractTests.swift`**, which is deliberately *not* platform-guarded — it runs against the real Keychain on Apple, the real Credential Manager on Windows, a real Secret Service provider on Linux, and a host-registered in-memory backend on Android. Adding a backend without adding a branch to `makeStore` leaves it unasserted, which is the one thing this suite exists to prevent.
- `HostBackendFixture.swift` registers that fixture through the **real** `@_cdecl` entry point. Keep it that way: a fixture that bypasses the C boundary tests nothing that matters.
- Tests must scope themselves to a unique service per run, so a failure cannot leave residue in a developer's real keychain and concurrent runs cannot collide.
- `swift build`, `swift test`, and `swift format lint --strict --recursive Sources Tests Package.swift` must pass before any commit. CI runs macOS, an iOS simulator, Linux, Windows, and an Android emulator; code must pass on all five. The Linux job installs `libsecret-1-dev` and starts gnome-keyring under `dbus-run-session`, so the suite runs against a real Secret Service rather than a stub.
- No force unwraps in tests either — use `try #require(...)`.

## Code Style

- 120 character line length
- 4-space indentation
- swift-format enforced (see `.swift-format`)
- No force unwraps in production code
- **NEVER use `try?` or `try!`. Ever.** Not in production code, not in tests, not in `defer`
  blocks, not in throwaway cleanup. `try?` silently discards the error, which is the exact
  failure-swallowing this package exists to prevent — and writing it here would contradict the
  premise that "absent" and "unreadable" are different. Use `do { try … } catch { … }`, or mark the
  function `throws` and propagate. `defer` cannot throw, so cleanup goes through a helper that
  records the failure (see `cleanUp` in the contract suite) rather than discarding it.
- No `DispatchQueue` — use Swift concurrency
- Prefer value types over reference types
- Documentation comments on all public API, explaining *why* where the reason is non-obvious

## Swift Patterns & Anti-Patterns

- **Never use caseless enums as namespaces.** Enums are for enumerated values. Use a `struct` with static members (see `SecureStoreStatus`).
- **`@convention(c)` for every bridge callback.** They cannot capture, which is precisely what makes them trivially `Sendable` and safe to hand to JNI. Per-call state travels through the explicit `context` pointer.
- **Mutex-guard the registry.** Registration lands on the host's startup thread while operations arrive from arbitrary concurrency contexts.
- **Do not share the registry across capabilities.** It is ~20 lines and the callback signatures differ enough between domains that a shared abstraction would leak. The *conventions* are the reusable part, and they live in `docs/design/host-bridge-abi.md`.

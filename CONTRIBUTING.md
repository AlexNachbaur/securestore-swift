# Contributing

Thanks for your interest in SecureStore.

## Getting set up

```bash
git clone https://github.com/AlexNachbaur/securestore-swift.git
cd securestore-swift
swift build
swift test
```

Swift 6.3 or newer is required — the manifest uses `swift-tools-version: 6.3` and older
toolchains cannot parse it.

To build and test the Android path you also need the
[Swift SDK for Android](https://www.swift.org/documentation/articles/swift-sdk-for-android-getting-started.html):

```bash
swift build --swift-sdk aarch64-unknown-linux-android28
swift test  --swift-sdk aarch64-unknown-linux-android28   # requires a device or emulator
```

CI runs the suite in an Android emulator, so a change that only compiles will still be caught.

## Before opening a pull request

```bash
make format   # swift format --in-place --recursive Sources Tests Package.swift
make check    # lint, build, test
```

## What a good change looks like

**Behaviour goes in the contract suite.** `Tests/SecureStoreTests/SecureStoreContractTests.swift`
is deliberately not platform-guarded: it runs against Keychain Services on Apple, Credential
Manager on Windows, a real Secret Service on Linux, and a host-registered in-memory backend on
Android. If you are changing what a store *does*, assert it
there so every backend is held to it. Backend-specific tests are for backend-specific mechanics
only.

**Keep platform concepts out of the shared API.** The cross-platform surface must not name
anything Apple-only. `namespace` is not called `accessGroup` for exactly this reason. If a feature
cannot be expressed without a platform term, that is a signal it belongs in a backend, not the
protocol.

**Reads throw.** Do not add convenience that turns a failure into `nil`. Conflating "no such item"
with "could not be read" is how a locked keychain becomes a mysterious signed-out user.

**Do not extend the C ABI casually.** It is a compatibility surface: a host compiled against one
version must keep working. Additive callbacks are fine; changing an existing signature is a
breaking change. The rules in [docs/design/host-bridge-abi.md](docs/design/host-bridge-abi.md) —
no heap pointers across the boundary, status codes for errors, non-capturing callbacks — are
requirements, not suggestions.

## Code review

Every pull request gets an automated review from Claude (`.github/workflows/claude-review.yml`),
which posts inline comments. `main` requires every review thread to be resolved before a merge:
fix what the comment describes, or reply with why it does not apply, then resolve it. A thread
resolved without either is reopened.

The review needs a secret that only this repository holds, so a pull request **from a fork** is
not reviewed automatically — a maintainer adds the `claude-review` label once they have looked
at the submission, which runs the review (and re-runs it on later pushes). Your fork's own copy
of the workflow skips itself, and the review is not a required check, so nothing about this
blocks you from building, testing, or opening the pull request.

## Reporting bugs

Use the [issue templates](https://github.com/AlexNachbaur/securestore-swift/issues/new/choose).
For a storage bug, please include the platform and — on a host-registered backend — how the host
was registered, since most surprises live at that boundary.

## Security

Do not open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md).

## License

Contributions are accepted under the [MIT License](LICENSE).

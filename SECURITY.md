# Security Policy

## Supported versions

SecureStore is pre-1.0. Only the latest release receives security fixes.

| Version | Supported |
|---|---|
| 0.2.x | ✅ |
| 0.1.x | ❌ |

## Reporting a vulnerability

**Do not open a public issue.**

Report privately through
[GitHub Security Advisories](https://github.com/AlexNachbaur/securestore-swift/security/advisories/new).
Please include the affected version and platform, what an attacker gains, and a reproduction if
you have one. You can expect an acknowledgement within a few days and an assessment shortly after;
fixes ship in a patch release with an advisory crediting you unless you prefer otherwise.

## Scope

This package stores secrets; the following are in scope:

- Values readable outside their intended `service` / `namespace` scope.
- Secrets reaching somewhere they should not — a log, a crash report, an error message, or an
  unexpected on-disk location.
- Memory-safety faults at the host bridge: a buffer read past its length, a use-after-free of a
  sink pointer, or a way for a host callback to corrupt Swift memory.
- Weaker-than-documented protection on Apple — items not honouring
  `kSecAttrAccessibleAfterFirstUnlock`, or ignoring the configured access group. One case is
  documented rather than a vulnerability: the macOS file-based keychain, the default on macOS,
  ignores both attributes by design of the platform. `KeychainSecureStore` enforces them on
  macOS only when created with `usesDataProtectionKeychain: true`; a store created that way
  which still leaked across namespaces would be in scope.

## What the platform stores do and do not protect

SecureStore adds no cryptography of its own. A value is exactly as protected as the platform
store it lands in, and those are not equivalent. This is how each one behaves by design, so none
of it is a vulnerability in this package — but all of it belongs in your threat model before you
choose what to store.

- **Other processes running as the same user can read the items on Windows and Linux.**
  Credential Manager scopes a generic credential to the user's logon session, not to the
  application that wrote it: any process running as that user can enumerate and read it. The
  Secret Service is the same once the keyring is unlocked — any client on the user's session bus
  can search for and read any item. `service` and `namespace` keep well-behaved stores from
  colliding with one another; on these two platforms they are not an access-control boundary
  against other software the user runs.
- **Names are not secret.** On Windows the service, namespace and key are joined into the
  credential's target name; on Linux they are stored as item attributes. Both are held
  unencrypted and are visible to anything that can list the store, without unlocking it on
  Linux. Only the *value* is protected — do not put anything sensitive in a service, namespace
  or key. An account identifier in a key (`"session.<accountID>"`) is disclosed to that extent.
- **Values are not wiped from memory.** A secret passes through `Data` on its way in and out,
  and neither this package nor Foundation zeroes those buffers on release.
- **On Apple, items are stored with `kSecAttrAccessibleAfterFirstUnlock`**, so they are
  readable while the device is locked after its first unlock, and are included in encrypted
  backups.

## Not in scope

- **The security of a host-registered backend.** On Android the *host* implements storage; which
  Keystore alias it uses, which cipher, and whether it requires user authentication are its
  decisions. Report those to that application. This package's responsibility ends at the ABI
  contract.
- **Physical extraction from a compromised device**, or a jailbroken/rooted OS. Platform secure
  storage is not designed to withstand an attacker with that level of access, and neither is this.
- **Choosing what to store.** Storing something that should not be persisted is an application
  decision.

## A note on the C bridge

The host bridge is the highest-risk surface here, and it is designed to shrink that risk: no heap
pointers cross the boundary in either direction, so there is nothing to leak or double-free, and
callbacks are non-capturing `@convention(c)` functions. If you find a way to violate either
property, that is a vulnerability — please report it.

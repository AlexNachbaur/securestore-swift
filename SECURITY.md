# Security Policy

## Supported versions

SecureStore is pre-1.0. Only the latest release receives security fixes.

| Version | Supported |
|---|---|
| 0.1.x | ✅ |

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
  `kSecAttrAccessibleAfterFirstUnlock`, or ignoring the configured access group.

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

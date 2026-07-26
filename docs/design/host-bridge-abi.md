# Host bridge ABI

How Swift reaches a secure store that lives outside Swift — Android's Keystore, or any other
host-provided implementation.

## Why a bridge at all

On Apple platforms `SecureStore` is satisfied natively: `KeychainSecureStore` calls Keychain
Services and there is nothing to bridge. Android has no Swift-native secure store. Its equivalent
is Java — `AndroidKeyStore`, usually reached through `EncryptedSharedPreferences` — and the
options for calling it from Swift are:

1. **Generate Java bindings** with `swift-java`/`jextract` in JNI mode, and call the Java API from
   Swift.
2. **Hand-write a JNI shim** in Swift, resolving classes and method IDs at runtime.
3. **Invert the direction** — the host implements the storage and Swift calls out to it.

This package takes (3). The surface is six operations over primitives, which is small enough that
a plain C boundary is simpler than either binding strategy — and it keeps `swift-java` off the
critical path, so the package builds with nothing but the Swift SDK for Android. It also puts the
platform-specific security decisions (which Keystore alias, which cipher, whether to require user
authentication) in the host, where they belong, rather than encoding one opinion in a library.

## The contract

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

### Rule 1 — no heap pointers cross the boundary

Operations that produce a value do **not** return a pointer. The host invokes the supplied *sink*
with a pointer and a length; Swift copies inside the callback's lifetime; the host frees its own
buffer when the call returns.

The alternative — returning a malloc'd buffer for Swift to free — requires both sides to agree on
an allocator and to keep agreeing across every future change. Sinks make that impossible to get
wrong: ownership never changes hands.

`keys` uses the same mechanism, invoking the sink once per matching key.

### Prefix, not pattern

`keys` filters by **prefix** and nothing richer. That is not a simplification for its own sake — it
is what the platforms provide. Windows Credential Manager's `CredEnumerateW` documents its filter
as *"a name prefix followed by an asterisk"*, so a general glob or regex would have to be emulated
in Swift on every platform, discarding the native filtering that makes enumeration cheap.

An empty prefix means every key. Hosts whose platform filters natively should push the prefix down
rather than enumerate everything and discard; hosts that cannot may filter themselves.

This is what makes one-item-per-credential practical rather than packing many credentials into a
single blob — the latter forces a read-modify-write on every update and runs into per-item size
ceilings (Windows caps a credential blob at `CRED_MAX_CREDENTIAL_BLOB_SIZE`, 2,560 bytes).

### Rule 2 — every operation returns a status

| Status | Meaning |
|---|---|
| `0` | Success |
| `1` | No such item. **Not an error** for reads or removals |
| other | Host failure, surfaced as `SecureStoreError.platform(code:)` |

Reporting the host's own code verbatim matters in the field: a support report can be traced to a
specific platform error rather than a generic "keychain failed".

### Rule 3 — callbacks cannot capture

Every function pointer is `@convention(c)`, so it cannot close over Swift context. This is a
feature, not a limitation: non-capturing pointers are trivially `Sendable`, safe to call from any
thread, and directly expressible from JNI. Per-call context travels through the explicit
`void *context` parameter instead.

### Rule 4 — register before use, exactly once

Registration is expected during host startup — on Android, `Application.onCreate`, which precedes
any Swift entry point. Registration is mutex-guarded because it lands on the host's startup thread
while store operations arrive from arbitrary Swift concurrency contexts.

Before registration every operation throws `SecureStoreError.backendNotRegistered`. It does not
silently succeed: a credential store that appears to work while persisting nothing is a far worse
failure than an obvious one, and it would surface much later as an inexplicable signed-out user.

## Host obligations

A conforming host must:

- **Scope items by `service` *and* `namespace`.** Two stores differing only in service must not
  see each other's items. `namespace` may be `NULL`.
- **Match prefixes literally.** `keys` with prefix `"session"` must return `"session"` and
  `"session.alice"` but not `"presession"`. It is a prefix test, not a substring search.
- **Treat `set` as upsert.** Writing an existing key replaces its value; it must not duplicate.
- **Preserve bytes exactly**, including embedded NULs and empty values. Values are arbitrary
  binary, not strings. A zero-length value is a stored value, distinct from a missing one.
- **Return `1`, not an error**, when removing something absent — the caller's desired end state is
  already true.
- **Not retain the pointers** passed into `set`; copy what it needs before returning.

The contract suite in `Tests/SecureStoreTests` asserts every one of these against an in-memory
host registered through the real entry point, so a host implementation can be validated by running
the same tests.

## Reusing this pattern

The same shape — a protocol, a compile-time Apple conformer, a host-registered conformer over C
callbacks, and a `@_cdecl` registration point — generalises to any capability whose implementation
lives outside Swift.

What generalises is the **conventions above**, not code. The registry itself is roughly twenty
lines and is deliberately duplicated per capability rather than shared, because the callback
signatures differ so much between domains that a shared abstraction would leak: a fire-and-forget
telemetry bridge needs no sinks and no statuses at all, while this one is built around both.

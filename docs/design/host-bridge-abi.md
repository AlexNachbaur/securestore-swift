# Host bridge ABI

How Swift reaches a secure store that lives outside Swift — Android's Keystore, or any other
host-provided implementation.

## Scope

This bridge covers the platforms whose secure store is *not* reachable from Swift. That is now
Android alone; Apple, Windows and Linux all have native backends
(`KeychainSecureStore`, `WindowsSecureStore`, `LinuxSecureStore`), and the host bridge does not
compile on any of them. If a future platform is added with no Swift-reachable store, it joins
Android under this same ABI rather than getting a fifth bespoke backend.

## Why a bridge at all

On Apple platforms `SecureStore` is satisfied natively: `KeychainSecureStore` calls Keychain
Services and there is nothing to bridge. The same is true of Windows (Credential Manager, via
the Win32 `Cred*` functions) and Linux (the freedesktop.org Secret Service, via libsecret) —
both are plain C APIs that Swift can call directly.

Android is the exception. It has no Swift-native secure store; its equivalent is Java —
`AndroidKeyStore`, usually reached through `EncryptedSharedPreferences` — and the options for
calling it from Swift are:

1. **Generate Java bindings** with `swift-java`/`jextract` in JNI mode, and call the Java API from
   Swift.
2. **Hand-write a JNI shim** in Swift, resolving classes and method IDs at runtime.
3. **Invert the direction** — the host implements the storage and Swift calls out to it.

This package takes (3). The surface is five operations over primitives, which is small enough that
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

The same declarations, with named function-pointer types and the status constants, are
available as a C header in [securestore_host.h](securestore_host.h). It is a reference copy for
a JNI shim to include — nothing in the Swift package builds against it.

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
(`WindowsSecureStore` now pushes the prefix into `CredEnumerateW` for exactly this reason, which
makes the constraint a demonstrated one rather than an anticipated one.)

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
| other | Host failure, surfaced as `SecureStoreError.platform(PlatformFailure)` |

For `get`, `0` carries a second obligation: the sink must have been called. A host that returns
`0` without calling it has claimed an item exists and then delivered nothing, and Swift reports
that as `SecureStoreError.invalidData` — **not** as a missing item. Treating it as missing would
turn a host that failed inside its own lookup into a silently signed-out user, which is the one
outcome this package exists to rule out. If the item is absent, return `1`.

One failure is raised by Swift without the host being called: a value longer than `INT32_MAX`
bytes cannot be expressed in `set`'s `int32_t length`, so the write throws a `PlatformFailure`
for the host backend with code `0` and a message giving the size. Code `0` is used because it is
the one value a host can never report as a failure, so it cannot be mistaken for a host code.

Reporting the host's own code verbatim matters in the field: a support report can be traced to a
specific platform error rather than a generic "keychain failed".

### Rule 2a — describing a status (optional)

A code alone is meaningful to whoever wrote the host and opaque to everyone else. The native
backends do better — Apple resolves an `OSStatus` through `SecCopyErrorMessageString`, Windows
through `FormatMessageW`, Linux carries libsecret's own `GError` message — and a host can too:

```c
void securestore_register_host_describer(
    void (*describe)(int32_t status,
                     void *context,
                     void (*sink)(void *context, const char *message)));
```

The text comes back through a sink, following Rule 1 exactly as `get` and `keys` do — the host
keeps ownership and Swift copies within the call.

**This is a separate symbol, not a parameter added to `securestore_register_host`.** Adding a
parameter would change an existing signature and break every host already compiled against it,
which the compatibility rule forbids. A new entry point is additive: a host that never calls it
links and runs unchanged, and its failures simply carry a code and no text — exactly the
behaviour that existed before this was added.

Registering a describer is optional and independent of registering the callback table; there is
no ordering requirement between them.

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

Rules 1 to 4 follow from the signatures. Rules 5 to 7 cover what the signatures leave unsaid —
encoding, threads, and `NULL` — and they are where a JNI shim most often goes wrong.

### Rule 5 — strings are standard UTF-8

Every `const char *` in the ABI — `service`, `namespace_`, `key`, `prefix` going in; keys and
describer messages coming back through sinks — is a NUL-terminated string in **standard UTF-8**.
Swift produces them with `withCString` and reads them with `String(cString:)`.

That is **not** the encoding JNI's string functions use. `NewStringUTF` and `GetStringUTFChars`
speak *Modified* UTF-8, which differs from the standard in two ways: a character outside the
Basic Multilingual Plane (an emoji, say) is written as a surrogate pair of two three-byte
sequences rather than one four-byte sequence, and U+0000 is written as `0xC0 0x80`. For plain
ASCII the two encodings are identical, which is exactly why this goes unnoticed until a real
user's key contains something else:

- Passing a Swift-supplied string to `NewStringUTF` hands it four-byte sequences it does not
  accept. The result is unspecified — a corrupted string on some runtimes, an abort under
  CheckJNI.
- Passing `GetStringUTFChars` output to a sink hands Swift surrogate halves, which are not valid
  UTF-8. `String(cString:)` repairs invalid input by substituting U+FFFD, so the key Swift
  receives is silently **not the key that was stored**, and will not match on the next lookup.

Convert through bytes instead, in both directions:

- **Swift → Java:** copy the C string into a `byte[]` (`NewByteArray` + `SetByteArrayRegion`) and
  decode it on the Java side with `new String(bytes, StandardCharsets.UTF_8)`.
- **Java → Swift:** `string.getBytes(StandardCharsets.UTF_8)`, copy into a NUL-terminated native
  buffer (`GetByteArrayRegion`), pass that to the sink, and free it after the sink returns.

Two limits follow from these being C strings. A string cannot contain U+0000: a key, service or
namespace with an embedded NUL is cut off at it when it crosses the boundary. And string
*values* are not a thing here — the stored value is a byte buffer with an explicit length (see
"Preserve bytes exactly" below), so it may contain anything.

### Rule 6 — callbacks run on the caller's thread

Swift invokes a callback **synchronously, on whichever thread called the `SecureStore` method**.
Usually that is a Swift concurrency pool thread; it is never guaranteed to be the main thread,
and it is not necessarily attached to the JVM. The call does not return to Swift until the
callback returns, so a callback that blocks — on user authentication, for instance — blocks the
Swift caller for exactly as long. There is no timeout and no cancellation on the Swift side.

A JNI shim therefore has to:

- **Obtain a `JNIEnv` per call, never cache one.** A `JNIEnv *` is valid only on the thread it
  was issued to. Cache the `JavaVM *` (from `JNI_OnLoad`) instead, call `GetEnv`, and if it
  reports `JNI_EDETACHED` call `AttachCurrentThread`. Detach before returning if, and only if,
  this call did the attaching.
- **Resolve classes during registration, not inside a callback.** `FindClass` on a natively
  attached thread searches the system class loader and will not find the application's classes.
  Look up the class and method IDs once at registration, on a thread that came from Java, and
  hold the class through a global reference.
- **Release local references.** A natively attached thread never returns to Java, so nothing
  frees them automatically: use `PushLocalFrame`/`PopLocalFrame`, or delete each one.
- **Never return with a Java exception pending.** Check `ExceptionCheck` after every call into
  Java, clear it, and report the failure as a non-zero status. Swift cannot see a pending
  exception; it would surface later, somewhere unrelated.
- **Call the sink before returning, on the same thread.** The `context` pointer refers to Swift
  stack storage that ceases to exist when the callback returns. A sink invoked later, or from
  another thread, writes through a dangling pointer.

Callbacks may also run **concurrently** with one another: Swift does not serialise calls, so
several threads may be inside the host at once. The host is responsible for its own
synchronisation.

### Rule 7 — what may be `NULL`

| Pointer | May be `NULL`? |
|---|---|
| Any function pointer passed to `securestore_register_host` or `securestore_register_host_describer` | **No.** Undefined behaviour — see below |
| `service`, `key`, `prefix` | No. Swift never passes `NULL` |
| `namespace_` | **Yes** — `NULL` means the store has no namespace. Never an empty string |
| `bytes` passed to `set` | No, but with `length` `0` it points at nothing readable and must not be dereferenced |
| `context`, and the `sink` Swift supplies | No. Pass `context` back to the sink unchanged; do not interpret it |
| `bytes` passed to the data sink | Only with `length` `0`. `NULL` with a positive length makes the read throw `invalidData` |
| `key` / `message` passed to a key or message sink | Tolerated: the call is ignored |

The registration functions cannot check their arguments. They are Swift functions exported with
`@_cdecl`, and their parameters are non-optional function types: Swift assumes the pointers are
valid and there is no `NULL` it could test for. A `NULL` callback is therefore undefined
behaviour — in practice a crash on the first operation that reaches it, not at registration. A
host that cannot support an operation should register a function that returns an error status.

Likewise, a length handed to the data sink must be non-negative. A negative length makes the
read throw `SecureStoreError.invalidData` rather than being treated as an empty value.

## Host obligations

A conforming host must:

- **Scope items by `service` *and* `namespace`.** Two stores differing only in service must not
  see each other's items. `namespace` may be `NULL`.
- **Match prefixes literally.** `keys` with prefix `"session"` must return `"session"` and
  `"session.alice"` but not `"presession"`. It is a prefix test, not a substring search.
- **Treat `set` as upsert.** Writing an existing key replaces its value; it must not duplicate.
- **Preserve bytes exactly**, including embedded NULs and empty values. Values are arbitrary
  binary, not strings. A zero-length value is a stored value, distinct from a missing one.
- **Preserve keys exactly**, as the UTF-8 byte sequences they arrived as. Do not normalise,
  case-fold, or round-trip them through Modified UTF-8 (Rule 5).
- **Call the `get` sink exactly once for an item that exists**, and never for one that does not.
- **Be safe to call from any thread, concurrently** (Rule 6).
- **Return `1`, not an error**, when removing something absent — the caller's desired end state is
  already true.
- **Not retain the pointers** passed into `set`; copy what it needs before returning.

The contract suite in `Tests/SecureStoreTests` asserts the behavioural obligations above against
an in-memory host registered through the real entry point, which is how the Swift side of the
ABI is kept honest. It does **not** validate *your* host: the suite always installs its own
in-memory fixture (`HostBackendFixture`), so running it tells you nothing about a real backend.
There is currently no supported way to point it at one. Until there is, treat the list above as a
checklist and assert it from your own host's tests — the cases in
`SecureStoreContractTests.swift` are short, and translate directly.

## Reusing this pattern

The same shape — a protocol, a compile-time Apple conformer, a host-registered conformer over C
callbacks, and a `@_cdecl` registration point — generalises to any capability whose implementation
lives outside Swift.

What generalises is the **conventions above**, not code. The registry itself is roughly twenty
lines and is deliberately duplicated per capability rather than shared, because the callback
signatures differ so much between domains that a shared abstraction would leak: a fire-and-forget
telemetry bridge needs no sinks and no statuses at all, while this one is built around both.

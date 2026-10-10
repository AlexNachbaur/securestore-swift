/*
 * securestore_host.h — C declarations for the SecureStore host bridge.
 *
 * REFERENCE COPY. This header is documentation: nothing in the Swift package includes it, and
 * it is not part of any build target. The two functions it declares are exported by the
 * SecureStore library itself (via `@_cdecl`) on platforms served by the host bridge — Android,
 * and any other platform with no Swift-reachable secure store. Copy this file into the JNI
 * shim that registers your backend.
 *
 * The contract these declarations summarise is specified in host-bridge-abi.md, alongside this
 * file. Where the two disagree, the Swift source (Sources/SecureStore/HostSecureStore.swift) is
 * authoritative and the disagreement is a bug worth reporting.
 *
 * Conventions that hold for every function below:
 *
 *   - STRINGS are NUL-terminated, standard UTF-8, in both directions. Not JNI "Modified UTF-8":
 *     do not build Java strings from them with NewStringUTF, and do not hand
 *     GetStringUTFChars output to a sink. Convert through byte[] and StandardCharsets.UTF_8.
 *   - POINTERS ARE BORROWED. Every pointer passed in either direction is valid only until the
 *     call it was passed to returns. Copy what you need; never retain, never free the other
 *     side's memory.
 *   - THREADS. Callbacks are invoked synchronously on whichever thread called the Swift store.
 *     That thread is not necessarily attached to the JVM. A sink must be called on the same
 *     thread, before the callback returns.
 *   - NULL. No function pointer may be NULL, at registration or as a sink argument Swift
 *     supplies. `service`, `key` and `prefix` are never NULL. `namespace_` is NULL when the
 *     store has no namespace. `context` is opaque: pass it back to the sink unchanged.
 */

#ifndef SECURESTORE_HOST_H
#define SECURESTORE_HOST_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Status values. Any other value is a host error, surfaced verbatim to the Swift caller. */
#define SECURESTORE_STATUS_OK        ((int32_t)0)
#define SECURESTORE_STATUS_NOT_FOUND ((int32_t)1) /* not an error for get, remove, remove_all, keys */

/*
 * Receives one value from `get`. Call exactly once for an item that exists, and not at all for
 * one that does not. `bytes` may be NULL only when `length` is 0, which reports a stored, empty
 * value. A negative `length`, or NULL `bytes` with a positive `length`, makes the read fail.
 */
typedef void (*securestore_data_sink)(void *context, const uint8_t *bytes, int32_t length);

/* Receives one key from `keys`. Call once per matching key. A NULL `key` is ignored. */
typedef void (*securestore_key_sink)(void *context, const char *key);

/* Receives the text for one status code. Call at most once. A NULL `message` is ignored. */
typedef void (*securestore_message_sink)(void *context, const char *message);

/*
 * Stores `length` bytes under `key`, replacing any existing value. `bytes` is never NULL, but
 * when `length` is 0 it must not be read: store an empty value, which is distinct from none.
 */
typedef int32_t (*securestore_set_fn)(const char *service, const char *namespace_,
                                      const char *key, const uint8_t *bytes, int32_t length);

/*
 * Reads the value under `key` by passing it to `sink`, then returns SECURESTORE_STATUS_OK.
 * Returns SECURESTORE_STATUS_NOT_FOUND, without calling `sink`, if there is no such item.
 * Returning OK without having called `sink` is reported to the Swift caller as an error.
 */
typedef int32_t (*securestore_get_fn)(const char *service, const char *namespace_,
                                      const char *key, void *context,
                                      securestore_data_sink sink);

/* Removes the item under `key`. Returns SECURESTORE_STATUS_NOT_FOUND if there was none. */
typedef int32_t (*securestore_remove_fn)(const char *service, const char *namespace_,
                                         const char *key);

/* Removes every item in `service` + `namespace_`. */
typedef int32_t (*securestore_remove_all_fn)(const char *service, const char *namespace_);

/*
 * Passes every key beginning with `prefix` to `sink`. An empty `prefix` means every key. The
 * match is a literal prefix test, not a substring or pattern match.
 */
typedef int32_t (*securestore_keys_fn)(const char *service, const char *namespace_,
                                       const char *prefix, void *context,
                                       securestore_key_sink sink);

/* Describes `status` by passing text to `sink`, or returns without calling it if unknown. */
typedef void (*securestore_describe_fn)(int32_t status, void *context,
                                        securestore_message_sink sink);

/*
 * Installs the host's secure-store implementation. Call during startup, before any store is
 * used; until then every Swift operation fails with `backendNotRegistered`. All five pointers
 * are required and none may be NULL.
 */
void securestore_register_host(securestore_set_fn set,
                               securestore_get_fn get,
                               securestore_remove_fn remove,
                               securestore_remove_all_fn remove_all,
                               securestore_keys_fn keys);

/*
 * Optionally installs a translator from the host's status codes to text. Independent of
 * securestore_register_host, with no ordering requirement. `describe` must not be NULL — a
 * host with nothing to describe simply does not call this.
 */
void securestore_register_host_describer(securestore_describe_fn describe);

#ifdef __cplusplus
}
#endif

#endif /* SECURESTORE_HOST_H */

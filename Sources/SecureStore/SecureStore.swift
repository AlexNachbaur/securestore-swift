import Foundation

/// Secure, persistent storage for small secrets — tokens, credentials, keys.
///
/// Backed by Keychain Services on Apple platforms and by a host-registered backend elsewhere
/// (see `HostSecureStore`). Callers never learn which.
///
/// Every operation is throwing, including reads. Silently swallowing a keychain failure hides
/// exactly the class of bug that matters here — a credential that appears absent because the
/// item was locked or the entitlement was wrong reads as "signed out" rather than as an error.
public protocol SecureStore: Sendable {

    /// Stores `data` under `key`, replacing any existing value.
    func set(_ data: Data, for key: String) throws

    /// Returns the value stored under `key`, or `nil` if no item exists.
    ///
    /// A missing item is `nil`; any other failure throws. The distinction matters: absent and
    /// unreadable demand different handling.
    func data(for key: String) throws -> Data?

    /// Removes the item stored under `key`. Removing a key that does not exist is not an error.
    func remove(_ key: String) throws

    /// Removes every item in this store's service + namespace.
    func removeAll() throws

    /// Keys in this store's service + namespace that begin with `prefix`, in unspecified order.
    ///
    /// Pass `""` for every key. Prefix — rather than a general pattern — is the primitive because
    /// it is what the underlying platforms actually offer: Windows Credential Manager's
    /// `CredEnumerateW` filter is documented as "a name prefix followed by an asterisk" and
    /// supports nothing richer, so anything more expressive would have to be emulated in Swift on
    /// every platform.
    ///
    /// This is what makes one-item-per-credential practical: store `"session.\(accountID)"` per
    /// account and enumerate them with `keys(withPrefix: "session.")`, instead of packing every
    /// account into a single blob.
    func keys(withPrefix prefix: String) throws -> [String]
}

extension SecureStore {

    /// Every key currently stored in this store's service + namespace, in unspecified order.
    public func allKeys() throws -> [String] {
        try keys(withPrefix: "")
    }
}

// MARK: - Configuration

/// Identifies one logical store.
public struct SecureStoreConfiguration: Sendable, Equatable {

    /// Groups related items. On Apple this is the keychain service attribute.
    public let service: String

    /// An opaque sharing scope, or `nil` for the calling process only.
    ///
    /// Deliberately **not** called `accessGroup`. On Apple it maps to a keychain access group,
    /// which lets an app and its extensions read the same items. Android's Keystore has no
    /// equivalent — storage there is per-app — so exposing the Apple concept would bake a
    /// platform assumption into a cross-platform API. Hosts that cannot honour a namespace
    /// should ignore it rather than fail.
    public let namespace: String?

    public init(service: String, namespace: String? = nil) {
        self.service = service
        self.namespace = namespace
    }
}

// MARK: - Errors

/// A failure from the underlying secure store.
public enum SecureStoreError: Error, Equatable, Sendable {

    /// The platform store reported a failure. See ``PlatformFailure``.
    case platform(PlatformFailure)

    /// Stored bytes could not be read back as data.
    case invalidData

    /// No backend has been registered yet on a host that requires one.
    ///
    /// Only reachable on hosts served by the C bridge, and only before the host calls its
    /// registration entry point.
    case backendNotRegistered
}

/// A failure reported by the platform's own store, with the context needed to act on it.
///
/// A bare status code is not enough. It does not say which store produced it, so the same
/// number means different things on different platforms; it does not say what was being
/// attempted, so a write failure is indistinguishable from an enumeration failure; and it
/// throws away any message the platform supplied. That combination is not hypothetical — a
/// missing Secret Service collection surfaces as writes failing while reads of absent keys
/// succeed, which reads as a backend bug until you find the message that says otherwise.
public struct PlatformFailure: Error, Equatable, Sendable, CustomStringConvertible {

    /// Which platform store reported the failure.
    ///
    /// Present because `code` is only meaningful alongside it: `-25300` is a Keychain
    /// `errSecItemNotFound`, `1168` is a Windows `ERROR_NOT_FOUND`, and a host backend's codes
    /// are whatever that host chose.
    public enum Backend: String, Equatable, Sendable {
        case keychain = "Keychain Services"
        case credentialManager = "Credential Manager"
        case secretService = "Secret Service"
        case host = "host backend"
    }

    /// Which `SecureStore` operation was in flight.
    public enum Operation: String, Equatable, Sendable {
        case set
        case read
        case remove
        case removeAll = "removeAll"
        case listKeys = "key enumeration"
    }

    public let backend: Backend
    public let operation: Operation

    /// The raw platform status: an `OSStatus` on Apple, a Win32 error on Windows, a `GError`
    /// code on Linux, or the host's own status through the C bridge.
    public let code: Int32

    /// The platform's own description, where it offers one.
    ///
    /// `nil` when the platform has no message to give — notably a host backend that has not
    /// registered a describer, since the C bridge carries only a status code by itself.
    public let message: String?

    /// The error domain the code belongs to, where the platform namespaces its codes.
    ///
    /// Populated on Linux from the `GError` domain, because a Secret Service failure may come
    /// from libsecret, GIO, or D-Bus, and the same number means different things in each.
    /// `nil` on platforms with a single code space.
    public let domain: String?

    public init(
        backend: Backend,
        operation: Operation,
        code: Int32,
        message: String? = nil,
        domain: String? = nil
    ) {
        self.backend = backend
        self.operation = operation
        self.code = code
        self.message = message
        self.domain = domain
    }

    /// One line carrying everything above, for a log or a bug report.
    public var description: String {
        var text = "\(backend.rawValue) \(operation.rawValue) failed"
        if let domain {
            text += " (\(domain), code \(code))"
        } else {
            text += " (code \(code))"
        }
        if let message, !message.isEmpty {
            text += ": \(message)"
        }
        return text
    }
}

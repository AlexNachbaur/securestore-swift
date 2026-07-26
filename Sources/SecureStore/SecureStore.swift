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

    /// Every key currently stored in this store's service + namespace, in unspecified order.
    func allKeys() throws -> [String]
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

    /// The platform store reported a failure. `code` is the raw platform status —
    /// an `OSStatus` on Apple, the host's own status elsewhere — kept so a bug report can be
    /// traced back to a specific platform error rather than a generic one.
    case platform(code: Int32)

    /// Stored bytes could not be read back as data.
    case invalidData

    /// No backend has been registered yet on a host that requires one.
    ///
    /// Only reachable off Apple, and only before the host calls its registration entry point.
    case backendNotRegistered
}

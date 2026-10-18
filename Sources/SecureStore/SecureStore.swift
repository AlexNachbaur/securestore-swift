import Foundation

/// Secure, persistent storage for small secrets — tokens, credentials, keys.
///
/// Backed by Keychain Services on Apple platforms, Credential Manager on Windows, the
/// freedesktop.org Secret Service on Linux, and a host-registered backend everywhere else (see
/// `HostSecureStore`). `PlatformSecureStore` names whichever one the current platform has, so
/// callers never need to learn which.
///
/// Every operation is throwing, including reads. Silently swallowing a keychain failure hides
/// exactly the class of bug that matters here — a credential that appears absent because the
/// item was locked or the entitlement was wrong reads as "signed out" rather than as an error.
///
/// Every operation is also **synchronous, and may block for as long as the platform takes**.
/// That is usually microseconds, but not always: on Linux a locked keyring raises an unlock
/// prompt and the call does not return until the user answers or dismisses it, an Apple
/// keychain can do the same, and a host backend takes however long the host's implementation
/// does. There is no timeout and no cancellation — a blocked call ignores task cancellation —
/// so do not call a store from the main actor or from any context that must stay responsive.
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
    ///
    /// A namespace is therefore a sharing convenience, not an isolation boundary you can rely
    /// on everywhere: a backend may ignore it. The macOS file-based keychain is one that does —
    /// see `KeychainSecureStore` for the opt-in that makes it enforced there.
    public let namespace: String?

    /// Creates a configuration for the store identified by `service` and `namespace`.
    ///
    /// An empty `namespace` is normalized to `nil`: it is the absence of a scope, not a scope
    /// named `""`, and the backends would otherwise disagree about which of the two it means.
    public init(service: String, namespace: String? = nil) {
        self.service = service
        // An empty namespace is not a scope — it is the absence of one — so it is normalized to
        // `nil` here rather than left for each backend to interpret.
        //
        // This is load-bearing, not tidiness. Keychain Services and the host bridge can leave a
        // namespace out of a query entirely, but Credential Manager and the Secret Service have
        // to render one into a lookup key, and both spell "no namespace" as the empty string.
        // Without normalizing, `nil` and `""` would select the same items on those two backends
        // while remaining distinct on the other two — a store bleeding into another one on some
        // platforms and not others, which is exactly the class of divergence this package
        // exists to prevent.
        self.namespace = (namespace?.isEmpty ?? true) ? nil : namespace
    }
}

// MARK: - Errors

/// A failure from the underlying secure store.
///
/// Conforms to `LocalizedError` so that `error.localizedDescription` — which is what most
/// logging and alert code reaches for — carries the same text as the failure itself. Without
/// it Foundation substitutes "The operation couldn’t be completed", which discards exactly the
/// context `PlatformFailure` exists to preserve.
public enum SecureStoreError: Error, Equatable, Sendable, LocalizedError {

    /// The platform store reported a failure. See ``PlatformFailure``.
    case platform(PlatformFailure)

    /// Stored bytes could not be read back as data.
    ///
    /// The store answered, but what it handed back was not a usable value: a result of the
    /// wrong type, a missing buffer alongside a non-zero length, or a host that reported
    /// success without delivering anything. Distinct from a missing item, which is `nil`.
    case invalidData

    /// No backend has been registered yet on a host that requires one.
    ///
    /// Only reachable on hosts served by the C bridge, and only before the host calls its
    /// registration entry point.
    case backendNotRegistered

    /// One line describing the failure, for `localizedDescription`.
    public var errorDescription: String? {
        switch self {
        case .platform(let failure):
            failure.description
        case .invalidData:
            "The secure store returned a value that could not be read back as data"
        case .backendNotRegistered:
            "No secure-store backend has been registered by the host"
        }
    }
}

/// A failure reported by the platform's own store, with the context needed to act on it.
///
/// A bare status code is not enough. It does not say which store produced it, so the same
/// number means different things on different platforms; it does not say what was being
/// attempted, so a write failure is indistinguishable from an enumeration failure; and it
/// throws away any message the platform supplied. That combination is not hypothetical — a
/// missing Secret Service collection surfaces as writes failing while reads of absent keys
/// succeed, which reads as a backend bug until you find the message that says otherwise.
public struct PlatformFailure: Error, Equatable, Sendable, CustomStringConvertible, LocalizedError {

    /// Which platform store reported the failure.
    ///
    /// Present because `code` is only meaningful alongside it: `-25300` is a Keychain
    /// `errSecItemNotFound`, `1168` is a Windows `ERROR_NOT_FOUND`, and a host backend's codes
    /// are whatever that host chose.
    ///
    /// The raw value is the name used in ``PlatformFailure/description``.
    public enum Backend: String, Equatable, Sendable {
        /// Apple Keychain Services. `code` is an `OSStatus`.
        case keychain = "Keychain Services"
        /// Windows Credential Manager. `code` is a Win32 error.
        case credentialManager = "Credential Manager"
        /// The freedesktop.org Secret Service on Linux. `code` is a `GError` code, qualified by
        /// `domain`.
        case secretService = "Secret Service"
        /// A backend the host registered through the C bridge. `code` is the host's own status.
        case host = "host backend"
    }

    /// Which `SecureStore` operation was in flight.
    ///
    /// The raw value is the name used in ``PlatformFailure/description``.
    public enum Operation: String, Equatable, Sendable {
        /// `SecureStore.set(_:for:)`.
        case set
        /// `SecureStore.data(for:)`.
        case read
        /// `SecureStore.remove(_:)`.
        case remove
        /// `SecureStore.removeAll()`.
        case removeAll
        /// `SecureStore.keys(withPrefix:)`, and `allKeys()` through it.
        case listKeys = "key enumeration"
    }

    /// The platform store that reported the failure — and so the code space `code` belongs to.
    public let backend: Backend

    /// The operation that failed. A write failure and an enumeration failure with the same
    /// code call for different handling, and the code alone cannot tell them apart.
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

    /// Creates a failure. Public so a test double or a custom `SecureStore` conformer can
    /// report failures in the same shape the built-in backends do.
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

    /// The same line as ``description``, for `localizedDescription`.
    public var errorDescription: String? { description }
}

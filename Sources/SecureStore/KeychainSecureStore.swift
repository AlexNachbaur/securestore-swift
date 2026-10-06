#if canImport(Security)

    import Foundation
    import Security

    /// Wraps an `OSStatus` with the message Security Services has for it.
    ///
    /// `SecCopyErrorMessageString` is the framework's own lookup, so the text matches what
    /// Apple's tooling reports for the same status rather than a table maintained here that
    /// would drift.
    private func keychainFailure(_ status: OSStatus, _ operation: PlatformFailure.Operation)
        -> SecureStoreError
    {
        .platform(
            PlatformFailure(
                backend: .keychain,
                operation: operation,
                code: status,
                message: SecCopyErrorMessageString(status, nil) as String?
            )
        )
    }

    /// Writes an item that may or may not already exist, returning the final `OSStatus`.
    ///
    /// Keychain Services has no upsert, so a write is an add that falls back to an update when
    /// the item is already there. Those are two calls, and another process — an app and its
    /// extensions share a store — can delete the item between them: the add reports a
    /// duplicate, the update then finds nothing, and a write to a store that is perfectly
    /// healthy would fail with `errSecItemNotFound`. When that happens the item is known to be
    /// absent, so the add is tried once more.
    ///
    /// Once, not until it succeeds: losing the same race twice in a row means something is
    /// deleting this key continuously, and reporting that beats spinning on it.
    ///
    /// The two calls are parameters so the interleaving can be asserted directly. A real
    /// keychain cannot be made to lose this race on demand.
    func keychainUpsert(add: () -> OSStatus, update: () -> OSStatus) -> OSStatus {
        var status = errSecSuccess
        for _ in 0..<2 {
            status = add()
            guard status == errSecDuplicateItem else { return status }
            status = update()
            guard status == errSecItemNotFound else { return status }
        }
        return status
    }

    /// The backend `SecureStore` resolves to on this platform. See ``KeychainSecureStore``.
    ///
    /// Each backend file defines this under its own compile-time gate. The four gates are
    /// mutually exclusive and exhaustive, so exactly one definition exists in any build.
    public typealias PlatformSecureStore = KeychainSecureStore

    /// `SecureStore` over Apple Keychain Services.
    ///
    /// Items are `kSecClassGenericPassword`, keyed by service + account, which is the shape a
    /// token store wants: many named values under one service.
    ///
    /// Accessibility is `kSecAttrAccessibleAfterFirstUnlock` so credentials remain readable
    /// while the device is locked. That is required, not incidental — the notification service
    /// extension performs delta sync from a locked device and needs its token.
    ///
    /// ## macOS has two keychains, and only one honors `namespace`
    ///
    /// iOS, tvOS, watchOS, and visionOS have a single keychain — the *data protection*
    /// keychain — where the access group and the accessibility class are enforced. macOS also
    /// has the older *file-based* keychain (`login.keychain-db`), and it is the default there.
    /// The file-based keychain **ignores both attributes**: an item written with one
    /// `namespace` reads back under any other, or under none, and no accessibility class is
    /// recorded. Two stores that differ only in `namespace` are therefore the same store on
    /// macOS unless ``usesDataProtectionKeychain`` is set.
    ///
    /// The default cannot simply be flipped: the data protection keychain is available only to
    /// a process signed with a keychain entitlement (an app, or a tool with
    /// `keychain-access-groups`). An unsigned process — `swift run`, `swift test`, a plain
    /// command-line tool — is refused with `errSecMissingEntitlement` (-34018) on every call.
    public struct KeychainSecureStore: SecureStore {

        private let configuration: SecureStoreConfiguration

        /// Whether items live in the data protection keychain rather than the macOS
        /// file-based one.
        ///
        /// Set this on macOS when `namespace` isolation or the accessibility class has to be
        /// real — see the type's discussion. It has no effect on iOS, tvOS, watchOS, or
        /// visionOS, which have no other keychain.
        ///
        /// Two consequences worth knowing before turning it on:
        ///
        /// - The process must hold a keychain entitlement. Without one, every operation throws
        ///   ``SecureStoreError/platform(_:)`` carrying `errSecMissingEntitlement` (-34018) —
        ///   loudly, rather than falling back to the file-based keychain.
        /// - The two keychains do not share items. A store created with this set does not see
        ///   what the same service wrote without it, so changing the value on a shipped macOS
        ///   app needs a migration: read from the old store, write to the new one.
        public let usesDataProtectionKeychain: Bool

        /// Creates a store over the items identified by `configuration`.
        ///
        /// Nothing is read or written until the first operation, so this cannot fail.
        ///
        /// - Parameters:
        ///   - configuration: The service and namespace identifying the store.
        ///   - usesDataProtectionKeychain: See ``usesDataProtectionKeychain``. Off by default,
        ///     because an unentitled macOS process cannot use that keychain at all.
        public init(_ configuration: SecureStoreConfiguration, usesDataProtectionKeychain: Bool = false) {
            self.configuration = configuration
            self.usesDataProtectionKeychain = usesDataProtectionKeychain
        }

        /// Creates a store for `service`, optionally scoped to `namespace`.
        ///
        /// `service` becomes the keychain service attribute and `namespace` the keychain access
        /// group. See ``SecureStoreConfiguration`` for how an empty namespace is treated. On
        /// macOS the access group is honored only when `usesDataProtectionKeychain` is `true`.
        ///
        /// - Parameters:
        ///   - service: The keychain service attribute.
        ///   - namespace: The keychain access group, or `nil` for the process's default.
        ///   - usesDataProtectionKeychain: See ``usesDataProtectionKeychain``. Off by default,
        ///     because an unentitled macOS process cannot use that keychain at all.
        public init(service: String, namespace: String? = nil, usesDataProtectionKeychain: Bool = false) {
            self.init(
                SecureStoreConfiguration(service: service, namespace: namespace),
                usesDataProtectionKeychain: usesDataProtectionKeychain
            )
        }

        // MARK: - SecureStore

        public func set(_ data: Data, for key: String) throws {
            // Try to add first and fall back to update on duplicate, rather than
            // read-then-branch: the check-then-act version can lose a race with another
            // process writing the same item, and both app and extensions share this store.
            var attributes = baseQuery(for: key)
            attributes[kSecValueData as String] = data
            attributes[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock

            let query = baseQuery(for: key)
            let status = keychainUpsert(
                add: { SecItemAdd(attributes as CFDictionary, nil) },
                update: {
                    SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary)
                }
            )
            guard status == errSecSuccess else {
                throw keychainFailure(status, .set)
            }
        }

        public func data(for key: String) throws -> Data? {
            var query = baseQuery(for: key)
            query[kSecReturnData as String] = true
            query[kSecMatchLimit as String] = kSecMatchLimitOne

            var result: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &result)

            if status == errSecItemNotFound { return nil }
            guard status == errSecSuccess else {
                throw keychainFailure(status, .read)
            }
            guard let data = result as? Data else {
                throw SecureStoreError.invalidData
            }
            return data
        }

        public func remove(_ key: String) throws {
            let status = SecItemDelete(baseQuery(for: key) as CFDictionary)
            // Deleting something already absent is the caller's desired end state, not a failure.
            guard status == errSecSuccess || status == errSecItemNotFound else {
                throw keychainFailure(status, .remove)
            }
        }

        public func removeAll() throws {
            // `SecItemDelete` does NOT behave uniformly across Apple platforms: on iOS a query
            // matching several items deletes all of them, but on the macOS legacy keychain it
            // deletes exactly one. (Verified: adding two items under one service and issuing a
            // single service-scoped delete leaves one behind.) Loop until the store reports
            // nothing left, rather than assuming the iOS semantics.
            while true {
                let status = SecItemDelete(serviceQuery() as CFDictionary)
                if status == errSecItemNotFound { return }
                guard status == errSecSuccess else {
                    throw keychainFailure(status, .removeAll)
                }
            }
        }

        public func keys(withPrefix prefix: String) throws -> [String] {
            var query = serviceQuery()
            query[kSecReturnAttributes as String] = true
            query[kSecMatchLimit as String] = kSecMatchLimitAll

            var result: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &result)

            if status == errSecItemNotFound { return [] }
            guard status == errSecSuccess else {
                throw keychainFailure(status, .listKeys)
            }
            guard let items = result as? [[String: Any]] else {
                throw SecureStoreError.invalidData
            }

            // Keychain Services has no prefix predicate — `kSecMatchSubjectStartsWith` applies to
            // certificates, not generic-password accounts — so the filter happens here. The item
            // set is scoped to one service, so this is a small in-memory pass, not a full
            // keychain scan.
            let accounts = items.compactMap { $0[kSecAttrAccount as String] as? String }
            guard !prefix.isEmpty else { return accounts }
            return accounts.filter { $0.hasPrefix(prefix) }
        }

        // MARK: - Queries

        /// Attributes identifying this store — everything except the account.
        private func serviceQuery() -> [String: Any] {
            var query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: configuration.service,
            ]
            if let namespace = configuration.namespace {
                query[kSecAttrAccessGroup as String] = namespace
            }
            // Part of the store's identity, so it rides on every query: the same service names
            // different items in each keychain. Only ever set to true — an explicit `false`
            // is not the same as absent on every OS version.
            if usesDataProtectionKeychain {
                query[kSecUseDataProtectionKeychain as String] = true
            }
            return query
        }

        /// Attributes identifying a single item.
        private func baseQuery(for key: String) -> [String: Any] {
            var query = serviceQuery()
            query[kSecAttrAccount as String] = key
            return query
        }
    }

#endif

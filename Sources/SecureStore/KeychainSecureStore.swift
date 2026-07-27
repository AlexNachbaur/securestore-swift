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

    /// `SecureStore` over Apple Keychain Services.
    ///
    /// Items are `kSecClassGenericPassword`, keyed by service + account, which is the shape a
    /// token store wants: many named values under one service.
    ///
    /// Accessibility is `kSecAttrAccessibleAfterFirstUnlock` so credentials remain readable
    /// while the device is locked. That is required, not incidental — the notification service
    /// extension performs delta sync from a locked device and needs its token.
    public struct KeychainSecureStore: SecureStore {

        private let configuration: SecureStoreConfiguration

        public init(_ configuration: SecureStoreConfiguration) {
            self.configuration = configuration
        }

        public init(service: String, namespace: String? = nil) {
            self.init(SecureStoreConfiguration(service: service, namespace: namespace))
        }

        // MARK: - SecureStore

        public func set(_ data: Data, for key: String) throws {
            // Try to add first and fall back to update on duplicate, rather than
            // read-then-branch: the check-then-act version can lose a race with another
            // process writing the same item, and both app and extensions share this store.
            var attributes = baseQuery(for: key)
            attributes[kSecValueData as String] = data
            attributes[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock

            let addStatus = SecItemAdd(attributes as CFDictionary, nil)
            if addStatus == errSecSuccess { return }

            guard addStatus == errSecDuplicateItem else {
                throw keychainFailure(addStatus, .set)
            }

            let updateStatus = SecItemUpdate(
                baseQuery(for: key) as CFDictionary,
                [kSecValueData as String: data] as CFDictionary
            )
            guard updateStatus == errSecSuccess else {
                throw keychainFailure(updateStatus, .set)
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

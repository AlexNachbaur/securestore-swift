#if os(Linux)

    import CSecret
    import Foundation

    // MARK: - Attributes
    //
    // The Secret Service identifies an item by a set of attributes rather than by one name, which
    // makes it the closest of the three native backends to Keychain Services: service, namespace
    // and key stay separate values and cannot bleed into one another the way they can in a
    // Windows target name.
    //
    // libsecret's `SecretSchema` is not used. Its purpose is to type-check attribute values, and
    // every attribute here is a string; constructing one from Swift means populating a 32-element
    // fixed C array imported as a tuple, which buys nothing but a way to get it wrong. Passing a
    // NULL schema and setting the conventional `xdg:schema` attribute by hand gives the same
    // isolation — items are matched on the full attribute set, so another application's
    // credentials can never be returned.

    /// Marks an item as belonging to SecureStore, in the attribute the Secret Service ecosystem
    /// conventionally uses for exactly this.
    private let schemaAttribute = "xdg:schema"
    private let schemaName = "dev.securestore.Item"

    /// Builds the attribute table identifying a store, or a single item within it.
    ///
    /// Passing `key: nil` yields the store-wide attribute set — which is what makes `removeAll`
    /// and `keys(withPrefix:)` a single Secret Service call rather than a client-side sweep.
    ///
    /// A `nil` namespace is stored as `""` rather than omitted. Omitting it would make a
    /// store-wide search match *every* namespace under the service, so an unscoped store would
    /// silently enumerate and delete a scoped one's items.
    private func makeAttributes(
        service: String,
        namespace: String?,
        key: String?
    ) -> OpaquePointer? {
        guard
            let table = g_hash_table_new_full(
                g_str_hash,
                g_str_equal,
                { g_free($0) },
                { g_free($0) }
            )
        else { return nil }

        func insert(_ name: String, _ value: String) {
            g_hash_table_insert(table, g_strdup(name), g_strdup(value))
        }

        insert(schemaAttribute, schemaName)
        insert("service", service)
        insert("namespace", namespace ?? "")
        if let key { insert("key", key) }
        return table
    }

    // libsecret's two handle types import differently, and the difference is not cosmetic.
    //
    // `SecretItem` is a GObject with a public struct, so `SecretItem *` arrives as a typed
    // `UnsafeMutablePointer<SecretItem>`. `SecretValue` is an opaque boxed type, so
    // `SecretValue *` arrives as an `OpaquePointer` — and its refcounting helpers are declared
    // against bare `gpointer` rather than the type, so releasing one needs an explicit cast.
    // `GList` payloads are `gpointer`-erased and have to be bound back to a type by hand.
    //
    // These two shims exist so that conversion noise stays out of the operations themselves.

    /// Releases a `SecretValue`, whose unref helper takes an untyped `gpointer`.
    private func releaseValue(_ value: OpaquePointer) {
        secret_value_unref(UnsafeMutableRawPointer(value))
    }

    /// Binds a `GList` node's erased payload back to `SecretItem`.
    private func secretItem(_ payload: UnsafeMutableRawPointer) -> UnsafeMutablePointer<SecretItem> {
        payload.assumingMemoryBound(to: SecretItem.self)
    }

    /// Translates a `GError` into a `SecureStoreError`, freeing it.
    ///
    /// Both the message and the domain are carried across, and neither is optional detail here.
    /// A Secret Service call can fail through libsecret, GIO, or D-Bus, and those are separate
    /// code spaces — the same number means different things in each, so a bare code is not even
    /// unambiguous, let alone actionable. The message is frequently the entire diagnosis: a
    /// container with no default collection reports "Object does not exist at path
    /// /org/freedesktop/secrets/collection/login", which names the fix.
    private func consume(
        _ error: UnsafeMutablePointer<GError>,
        _ operation: PlatformFailure.Operation
    ) -> SecureStoreError {
        defer { g_error_free(error) }
        let message = error.pointee.message.map { String(cString: $0) }
        let domain = g_quark_to_string(error.pointee.domain).map { String(cString: $0) }
        return .platform(
            PlatformFailure(
                backend: .secretService,
                operation: operation,
                code: Int32(error.pointee.code),
                message: message,
                domain: domain
            )
        )
    }

    // MARK: - Store

    /// `SecureStore` over the freedesktop.org Secret Service, via libsecret.
    ///
    /// Items land in the user's default collection — the login keyring on a typical desktop —
    /// and searches unlock it on demand, so a locked keyring prompts rather than reading as
    /// empty. That distinction is the Linux face of the package's central rule: absent and
    /// unreadable are different, and a locked store must never masquerade as a signed-out user.
    ///
    /// Requires a running Secret Service provider (gnome-keyring, KWallet's Secret Service
    /// bridge, or KeePassXC). A headless host with no provider will fail loudly on first use
    /// rather than silently persisting nothing.
    public struct LinuxSecureStore: SecureStore {

        private let configuration: SecureStoreConfiguration

        public init(_ configuration: SecureStoreConfiguration) {
            self.configuration = configuration
        }

        public init(service: String, namespace: String? = nil) {
            self.init(SecureStoreConfiguration(service: service, namespace: namespace))
        }

        /// Runs `body` with the attribute table for `key` (or for the whole store when `nil`).
        private func withAttributes<Result>(
            key: String?,
            _ body: (OpaquePointer) throws -> Result
        ) throws -> Result {
            guard
                let table = makeAttributes(
                    service: configuration.service,
                    namespace: configuration.namespace,
                    key: key
                )
            else { throw SecureStoreError.invalidData }
            defer { g_hash_table_unref(table) }
            return try body(table)
        }

        /// A human-readable label, shown by keyring UIs such as Seahorse. Not an identifier —
        /// nothing is ever looked up by it.
        private func label(for key: String) -> String {
            "\(configuration.service): \(key)"
        }

        // MARK: - SecureStore

        public func set(_ data: Data, for key: String) throws {
            try withAttributes(key: key) { attributes in
                try data.withUnsafeBytes { buffer in
                    // `secret_value_new` copies, so the buffer only has to outlive this call.
                    // An empty `Data` has no base address; the length is what carries the
                    // meaning, and storing an empty value must stay distinct from storing
                    // nothing.
                    let bytes = buffer.bindMemory(to: CChar.self).baseAddress
                    guard
                        let value = secret_value_new(
                            bytes,
                            gssize(data.count),
                            "application/octet-stream"
                        )
                    else { throw SecureStoreError.invalidData }
                    defer { releaseValue(value) }

                    var error: UnsafeMutablePointer<GError>?
                    let stored = secret_service_store_sync(
                        nil,
                        nil,
                        attributes,
                        SECRET_COLLECTION_DEFAULT,
                        label(for: key),
                        value,
                        nil,
                        &error
                    )
                    if let error { throw consume(error, .set) }
                    guard stored != 0 else {
                        // libsecret reports failure through the GError, so a false return with
                        // no error should be unreachable. Surfacing it anyway beats returning
                        // as though the write succeeded.
                        throw SecureStoreError.platform(
                            PlatformFailure(
                                backend: .secretService,
                                operation: .set,
                                code: 0,
                                message: "libsecret reported failure without an error"
                            )
                        )
                    }
                }
            }
        }

        public func data(for key: String) throws -> Data? {
            let items = try search(key: key, loadSecrets: true, for: .read)
            defer { g_list_free_full(items, { g_object_unref($0) }) }

            // No match is `nil`, not an error. Anything that could not be read has already
            // thrown out of `search`.
            guard let first = items?.pointee.data else { return nil }

            guard let value = secret_item_get_secret(secretItem(first)) else {
                throw SecureStoreError.invalidData
            }
            defer { releaseValue(value) }

            var length: gsize = 0
            guard let bytes = secret_value_get(value, &length), length > 0 else {
                // Zero length means "stored, and empty" — absence was already handled above.
                return Data()
            }
            return Data(bytes: bytes, count: Int(length))
        }

        public func remove(_ key: String) throws {
            try clear(key: key, for: .remove)
        }

        public func removeAll() throws {
            try clear(key: nil, for: .removeAll)
        }

        public func keys(withPrefix prefix: String) throws -> [String] {
            let items = try search(key: nil, loadSecrets: false, for: .listKeys)
            defer { g_list_free_full(items, { g_object_unref($0) }) }

            var keys: [String] = []
            var node = items
            while let current = node {
                defer { node = current.pointee.next }
                guard let payload = current.pointee.data else { continue }
                guard let attributes = secret_item_get_attributes(secretItem(payload)) else {
                    continue
                }
                defer { g_hash_table_unref(attributes) }

                // The Secret Service matches attributes for equality only — there is no prefix
                // predicate to push down, unlike Windows — so the filter happens here. The item
                // set is already scoped to one service and namespace, so this is a small
                // in-memory pass rather than a scan of the user's whole keyring.
                guard let raw = g_hash_table_lookup(attributes, "key") else { continue }
                let key = String(cString: raw.assumingMemoryBound(to: CChar.self))
                if prefix.isEmpty || key.hasPrefix(prefix) { keys.append(key) }
            }
            return keys
        }

        // MARK: - Secret Service

        /// Items matching this store, optionally narrowed to one key.
        ///
        /// `SECRET_SEARCH_ALL` returns every match rather than just the first, and
        /// `SECRET_SEARCH_UNLOCK` unlocks the collection on demand so a locked keyring surfaces
        /// as a prompt or an error instead of an empty result.
        private func search(
            key: String?,
            loadSecrets: Bool,
            for operation: PlatformFailure.Operation
        ) throws -> UnsafeMutablePointer<GList>? {
            var flags = SECRET_SEARCH_ALL.rawValue | SECRET_SEARCH_UNLOCK.rawValue
            if loadSecrets { flags |= SECRET_SEARCH_LOAD_SECRETS.rawValue }

            return try withAttributes(key: key) { attributes in
                var error: UnsafeMutablePointer<GError>?
                let items = secret_service_search_sync(
                    nil,
                    nil,
                    attributes,
                    SecretSearchFlags(rawValue: flags),
                    nil,
                    &error
                )
                if let error { throw consume(error, operation) }
                return items
            }
        }

        /// Removes every item matching this store, optionally narrowed to one key.
        ///
        /// `secret_service_clear_sync` returns false when nothing matched, which is not a
        /// failure: absent is the caller's desired end state, matching every other backend.
        private func clear(key: String?, for operation: PlatformFailure.Operation) throws {
            try withAttributes(key: key) { attributes in
                var error: UnsafeMutablePointer<GError>?
                _ = secret_service_clear_sync(nil, nil, attributes, nil, &error)
                if let error { throw consume(error, operation) }
            }
        }
    }

#endif

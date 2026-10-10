#if os(Windows)

    import Foundation
    import WinSDK

    // MARK: - Target-name encoding
    //
    // Credential Manager is the odd one out among the native backends. Keychain Services and the
    // Secret Service both identify an item by a *set* of attributes, so service, namespace and
    // key stay separate values and cannot bleed into one another. Credential Manager has exactly
    // one identifier — `TargetName`, a single string — so the three components have to be
    // flattened into it.
    //
    // Flattening naively would let distinct stores collide: service `"a:b"` with key `"c"` and
    // service `"a"` with key `"b:c"` would produce the same name, and one app would silently read
    // another's secret. Each component is therefore escaped before joining.
    //
    // The escape is per-character, which is what keeps it *prefix-preserving*: if `key` begins
    // with `prefix`, then `escape(key)` begins with `escape(prefix)`. That property is what lets
    // `keys(withPrefix:)` push the filter down into `CredEnumerateW` instead of enumerating the
    // user's entire credential set and discarding most of it.

    /// The scheme marker, so SecureStore's credentials are distinguishable from every other
    /// application's in a Credential Manager the whole machine shares.
    private let targetNameScheme = "SecureStore"

    /// Escapes `%` and `:` so the joined target name can be split back unambiguously.
    ///
    /// `%` must be escaped first: doing it second would re-escape the `%` introduced by the
    /// colon rule and corrupt the round trip.
    ///
    /// The search is `.literal` on purpose. Foundation's default search matches whole composed
    /// characters, so a `:` followed by a combining mark is a different "character" and is
    /// skipped — leaving a raw separator in the target name, which is the collision this
    /// escaping exists to rule out. A target name is a sequence of code units, not of
    /// user-perceived characters, and has to be treated as one throughout.
    private func escape(_ component: String) -> String {
        component
            .replacingOccurrences(of: "%", with: "%25", options: .literal)
            .replacingOccurrences(of: ":", with: "%3A", options: .literal)
    }

    /// Inverse of `escape(_:)`. Applied in the reverse order for the same reason, and literal
    /// for the same reason.
    private func unescape(_ component: String) -> String {
        component
            .replacingOccurrences(of: "%3A", with: ":", options: .literal)
            .replacingOccurrences(of: "%25", with: "%", options: .literal)
    }

    /// Runs `body` with `string` as a NUL-terminated UTF-16 buffer.
    ///
    /// `CREDENTIALW` wants `LPWSTR` (mutable) even for fields it only reads, hence the
    /// `mutating:` cast. Nothing in the Win32 credential API writes through these pointers.
    private func withWideString<Result>(
        _ string: String,
        _ body: (UnsafeMutablePointer<WCHAR>) throws -> Result
    ) rethrows -> Result {
        try string.withCString(encodedAs: UTF16.self) { pointer in
            try body(UnsafeMutablePointer(mutating: pointer))
        }
    }

    /// The system's own text for a Win32 error code, or `nil` if it has none.
    ///
    /// `FORMAT_MESSAGE_FROM_SYSTEM` is the OS's message table, so this matches what every other
    /// Windows tool reports for the same code. `IGNORE_INSERTS` is required: without it,
    /// messages containing insert sequences expect an argument list and the call fails.
    ///
    /// A fixed buffer is used rather than `FORMAT_MESSAGE_ALLOCATE_BUFFER` because the latter
    /// returns a heap pointer to free via `LocalFree`, and the pointer arrives through a
    /// deliberately mistyped out-parameter — needless risk for a message that never approaches
    /// this length.
    private func systemMessage(for code: DWORD) -> String? {
        var buffer = [WCHAR](repeating: 0, count: 512)
        let length = buffer.withUnsafeMutableBufferPointer { buffer -> DWORD in
            guard let base = buffer.baseAddress else { return 0 }
            return FormatMessageW(
                DWORD(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS),
                nil,
                code,
                0,
                base,
                DWORD(buffer.count),
                nil
            )
        }
        guard length > 0 else { return nil }

        // System messages are conventionally terminated with CRLF, which is noise in a
        // single-line error description.
        let text = String(decodingCString: buffer, as: UTF16.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return text.isEmpty ? nil : text
    }

    /// Wraps a Win32 error code as a `SecureStoreError`.
    ///
    /// The code is a parameter rather than read here because `GetLastError` is only meaningful
    /// immediately after the call that failed: every subsequent Win32 call on the thread —
    /// including the one that formats the message, and whatever the Swift runtime does while
    /// unwinding a `withCString` scope — may overwrite it. Each call site therefore captures it
    /// exactly once, in the same expression as the failing call, and passes it along.
    ///
    /// `GetLastError` is `DWORD`; the bit pattern is preserved rather than clamped so a report
    /// can be traced back to the exact `ERROR_*` value.
    private func win32Failure(_ code: DWORD, _ operation: PlatformFailure.Operation) -> SecureStoreError {
        .platform(
            PlatformFailure(
                backend: .credentialManager,
                operation: operation,
                code: Int32(bitPattern: code),
                message: systemMessage(for: code)
            )
        )
    }

    // MARK: - Store

    /// The backend `SecureStore` resolves to on this platform. See ``WindowsSecureStore``.
    ///
    /// Each backend file defines this under its own compile-time gate. The four gates are
    /// mutually exclusive and exhaustive, so exactly one definition exists in any build.
    public typealias PlatformSecureStore = WindowsSecureStore

    /// `SecureStore` over the Windows Credential Manager.
    ///
    /// Items are `CRED_TYPE_GENERIC` credentials persisted with `CRED_PERSIST_LOCAL_MACHINE`, so
    /// they survive a sign-out on the machine that wrote them but do not roam to another one.
    /// Roaming (`CRED_PERSIST_ENTERPRISE`) is deliberately not used: a credential store for an
    /// application's own tokens should not be replicated to machines the user never authorised.
    ///
    /// Note the size ceiling. Credential Manager caps a blob at `CRED_MAX_CREDENTIAL_BLOB_SIZE`
    /// (2,560 bytes) — far smaller than Keychain Services allows. Storing more fails with a
    /// platform error rather than truncating, but it is a real portability limit for callers who
    /// were treating a secure store as general-purpose storage.
    public struct WindowsSecureStore: SecureStore {

        private let configuration: SecureStoreConfiguration

        /// Creates a store over the items identified by `configuration`.
        ///
        /// Nothing is read or written until the first operation, so this cannot fail.
        public init(_ configuration: SecureStoreConfiguration) {
            self.configuration = configuration
        }

        /// Creates a store for `service`, optionally scoped to `namespace`.
        ///
        /// Both are escaped and joined with the key into the credential's target name, so two
        /// stores differing in either never see each other's items.
        public init(service: String, namespace: String? = nil) {
            self.init(SecureStoreConfiguration(service: service, namespace: namespace))
        }

        // MARK: - Naming

        /// The shared leading portion of every target name in this store, key excluded.
        private var targetPrefix: String {
            let service = escape(configuration.service)
            let namespace = escape(configuration.namespace ?? "")
            return "\(targetNameScheme):\(service):\(namespace):"
        }

        private func targetName(for key: String) -> String {
            targetPrefix + escape(key)
        }

        /// Recovers the key from a full target name, or `nil` if the name belongs to another
        /// store. The prefix check is what makes an over-matching enumeration filter harmless.
        ///
        /// The store's prefix is matched by Unicode scalar, not with `hasPrefix`. `String`
        /// compares by user-perceived character, and a key that begins with a combining mark
        /// fuses with the `:` that ends the prefix into a single character — so `hasPrefix`
        /// reports that the name does not start with the prefix at all, and the item would
        /// vanish from `keys()` and be left behind by `removeAll()`. Dropping `prefix.count`
        /// characters has the same flaw in the other direction.
        private func key(fromTargetName name: String) -> String? {
            let prefix = targetPrefix.unicodeScalars
            let scalars = name.unicodeScalars
            guard scalars.starts(with: prefix) else { return nil }
            return unescape(String(scalars.dropFirst(prefix.count)))
        }

        // MARK: - SecureStore

        public func set(_ data: Data, for key: String) throws {
            // `CredentialBlobSize` is a 32-bit DWORD while `data.count` is a 64-bit Int, and
            // `DWORD(_:)` traps rather than truncating — so without this guard an oversized
            // value crashes the process instead of throwing. Credential Manager rejects
            // anything past CRED_MAX_CREDENTIAL_BLOB_SIZE (2,560 bytes) long before this point;
            // the guard exists so the unrepresentable case is a diagnosable error rather than a
            // crash, and the ordinary too-large case is left to Windows so the caller gets the
            // system's own message.
            guard data.count <= DWORD.max else {
                throw SecureStoreError.platform(
                    PlatformFailure(
                        backend: .credentialManager,
                        operation: .set,
                        code: Int32(bitPattern: DWORD(ERROR_INVALID_PARAMETER)),
                        message: """
                            Value is \(data.count) bytes; Credential Manager cannot store more \
                            than \(DWORD.max)
                            """
                    )
                )
            }

            let failure = withWideString(targetName(for: key)) { target -> DWORD? in
                data.withUnsafeBytes { buffer -> DWORD? in
                    guard let bytes = buffer.bindMemory(to: UInt8.self).baseAddress else {
                        // An empty `Data` has no base address, but `CREDENTIALW` still wants a
                        // non-null pointer alongside a zero length. Storing an empty value has
                        // to stay possible: it is distinct from storing nothing.
                        var placeholder: UInt8 = 0
                        return withUnsafeMutablePointer(to: &placeholder) {
                            write(target: target, bytes: $0, count: 0)
                        }
                    }
                    return write(
                        target: target,
                        bytes: UnsafeMutablePointer(mutating: bytes),
                        count: data.count
                    )
                }
            }
            if let failure { throw win32Failure(failure, .set) }
        }

        /// The `CredWriteW` call itself, returning the Win32 error if it failed and `nil` if it
        /// succeeded. `CredWriteW` replaces an existing credential with the same target name, so
        /// there is no add-then-update dance as on Apple.
        private func write(
            target: UnsafeMutablePointer<WCHAR>,
            bytes: UnsafeMutablePointer<UInt8>,
            count: Int
        ) -> DWORD? {
            var credential = CREDENTIALW()
            credential.Type = DWORD(CRED_TYPE_GENERIC)
            credential.TargetName = target
            credential.CredentialBlob = bytes
            credential.CredentialBlobSize = DWORD(count)
            credential.Persist = DWORD(CRED_PERSIST_LOCAL_MACHINE)
            return CredWriteW(&credential, 0) ? nil : GetLastError()
        }

        public func data(for key: String) throws -> Data? {
            var credential: PCREDENTIALW?
            let failure = withWideString(targetName(for: key)) { target -> DWORD? in
                CredReadW(target, DWORD(CRED_TYPE_GENERIC), 0, &credential) ? nil : GetLastError()
            }

            if let failure {
                // A missing item is `nil`, never an error — the distinction the whole package
                // exists to preserve.
                if failure == ERROR_NOT_FOUND { return nil }
                throw win32Failure(failure, .read)
            }
            guard let credential else { throw SecureStoreError.invalidData }
            defer { CredFree(credential) }

            // Zero length means "stored, and empty", which is not the same as absent —
            // absence was already handled by ERROR_NOT_FOUND above.
            let count = Int(credential.pointee.CredentialBlobSize)
            guard count > 0 else { return Data() }

            // A null blob alongside a non-zero length is a credential Credential Manager should
            // never hand back. Reporting it as empty would turn a corrupt item into a plausible
            // value, which is the same failure-swallowing the read path exists to prevent.
            guard let blob = credential.pointee.CredentialBlob else {
                throw SecureStoreError.invalidData
            }
            return Data(bytes: blob, count: count)
        }

        public func remove(_ key: String) throws {
            let failure = withWideString(targetName(for: key)) { target -> DWORD? in
                CredDeleteW(target, DWORD(CRED_TYPE_GENERIC), 0) ? nil : GetLastError()
            }
            if let failure {
                // Absent is the caller's desired end state, matching every other backend.
                if failure == ERROR_NOT_FOUND { return }
                throw win32Failure(failure, .remove)
            }
        }

        public func removeAll() throws {
            for name in try targetNames(matchingKeyPrefix: "", for: .removeAll) {
                let failure = withWideString(name) { target -> DWORD? in
                    CredDeleteW(target, DWORD(CRED_TYPE_GENERIC), 0) ? nil : GetLastError()
                }
                // A concurrent deleter winning the race leaves the desired end state anyway.
                if let failure, failure != ERROR_NOT_FOUND {
                    throw win32Failure(failure, .removeAll)
                }
            }
        }

        public func keys(withPrefix prefix: String) throws -> [String] {
            try targetNames(matchingKeyPrefix: prefix, for: .listKeys)
                .compactMap(key(fromTargetName:))
        }

        // MARK: - Enumeration

        /// Every target name in this store whose key begins with `keyPrefix`.
        ///
        /// `CredEnumerateW`'s filter is documented as "a name prefix followed by an asterisk", so
        /// the prefix is pushed down to Win32 rather than enumerating every credential on the
        /// machine. The results are re-checked in Swift regardless: the documented filter syntax
        /// says nothing about an asterisk appearing *inside* the prefix, which a caller's key
        /// could contain, and a backend that over-matched would hand one store another's items.
        ///
        /// That re-check goes through `key(fromTargetName:)`, which matches the store's own
        /// prefix by Unicode scalar, and then applies `keyPrefix` to the recovered key with the
        /// same `hasPrefix` the Keychain and Secret Service backends use — so what counts as a
        /// prefix is decided the same way on every platform, whatever `CredEnumerateW` returned.
        private func targetNames(
            matchingKeyPrefix keyPrefix: String,
            for operation: PlatformFailure.Operation
        ) throws -> [String] {
            let filter = targetPrefix + escape(keyPrefix) + "*"

            var count: DWORD = 0
            var credentials: UnsafeMutablePointer<PCREDENTIALW?>?
            let failure = withWideString(filter) { filter -> DWORD? in
                CredEnumerateW(filter, 0, &count, &credentials) ? nil : GetLastError()
            }

            if let failure {
                // No match at all is reported as a failure with ERROR_NOT_FOUND, not as an empty
                // set, so it has to be translated back into one.
                if failure == ERROR_NOT_FOUND { return [] }
                throw win32Failure(failure, operation)
            }
            guard let credentials else { return [] }
            defer { CredFree(credentials) }

            var names: [String] = []
            for index in 0..<Int(count) {
                guard let credential = credentials[index],
                    let targetName = credential.pointee.TargetName
                else { continue }
                let name = String(decodingCString: targetName, as: UTF16.self)
                guard let storedKey = key(fromTargetName: name) else { continue }
                guard keyPrefix.isEmpty || storedKey.hasPrefix(keyPrefix) else { continue }
                names.append(name)
            }
            return names
        }
    }

#endif

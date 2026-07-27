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
    private func escape(_ component: String) -> String {
        component
            .replacingOccurrences(of: "%", with: "%25")
            .replacingOccurrences(of: ":", with: "%3A")
    }

    /// Inverse of `escape(_:)`. Applied in the reverse order for the same reason.
    private func unescape(_ component: String) -> String {
        component
            .replacingOccurrences(of: "%3A", with: ":")
            .replacingOccurrences(of: "%25", with: "%")
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

    /// Wraps the calling thread's last Win32 error as a `SecureStoreError`.
    ///
    /// `GetLastError` is `DWORD`; the bit pattern is preserved rather than clamped so a report
    /// can be traced back to the exact `ERROR_*` value. It is read exactly once — every
    /// subsequent Win32 call, including the one that formats the message, would overwrite it.
    private func lastError(_ operation: PlatformFailure.Operation) -> SecureStoreError {
        let code = GetLastError()
        return .platform(
            PlatformFailure(
                backend: .credentialManager,
                operation: operation,
                code: Int32(bitPattern: code),
                message: systemMessage(for: code)
            )
        )
    }

    // MARK: - Store

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

        public init(_ configuration: SecureStoreConfiguration) {
            self.configuration = configuration
        }

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
        private func key(fromTargetName name: String) -> String? {
            let prefix = targetPrefix
            guard name.hasPrefix(prefix) else { return nil }
            return unescape(String(name.dropFirst(prefix.count)))
        }

        // MARK: - SecureStore

        public func set(_ data: Data, for key: String) throws {
            let written = withWideString(targetName(for: key)) { target -> Bool in
                data.withUnsafeBytes { buffer -> Bool in
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
            guard written else { throw lastError(.set) }
        }

        /// The `CredWriteW` call itself. `CredWriteW` replaces an existing credential with the
        /// same target name, so there is no add-then-update dance as on Apple.
        private func write(
            target: UnsafeMutablePointer<WCHAR>,
            bytes: UnsafeMutablePointer<UInt8>,
            count: Int
        ) -> Bool {
            var credential = CREDENTIALW()
            credential.Type = DWORD(CRED_TYPE_GENERIC)
            credential.TargetName = target
            credential.CredentialBlob = bytes
            credential.CredentialBlobSize = DWORD(count)
            credential.Persist = DWORD(CRED_PERSIST_LOCAL_MACHINE)
            return CredWriteW(&credential, 0)
        }

        public func data(for key: String) throws -> Data? {
            var credential: PCREDENTIALW?
            let read = withWideString(targetName(for: key)) { target in
                CredReadW(target, DWORD(CRED_TYPE_GENERIC), 0, &credential)
            }

            guard read else {
                // A missing item is `nil`, never an error — the distinction the whole package
                // exists to preserve.
                if GetLastError() == ERROR_NOT_FOUND { return nil }
                throw lastError(.read)
            }
            guard let credential else { throw SecureStoreError.invalidData }
            defer { CredFree(credential) }

            let count = Int(credential.pointee.CredentialBlobSize)
            guard count > 0, let blob = credential.pointee.CredentialBlob else {
                // Zero length means "stored, and empty", which is not the same as absent —
                // absence was already handled by ERROR_NOT_FOUND above.
                return Data()
            }
            return Data(bytes: blob, count: count)
        }

        public func remove(_ key: String) throws {
            let deleted = withWideString(targetName(for: key)) { target in
                CredDeleteW(target, DWORD(CRED_TYPE_GENERIC), 0)
            }
            guard deleted else {
                // Absent is the caller's desired end state, matching every other backend.
                if GetLastError() == ERROR_NOT_FOUND { return }
                throw lastError(.remove)
            }
        }

        public func removeAll() throws {
            for name in try targetNames(matchingKeyPrefix: "", for: .removeAll) {
                let deleted = withWideString(name) { target in
                    CredDeleteW(target, DWORD(CRED_TYPE_GENERIC), 0)
                }
                // A concurrent deleter winning the race leaves the desired end state anyway.
                if !deleted, GetLastError() != ERROR_NOT_FOUND {
                    throw lastError(.removeAll)
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
        private func targetNames(
            matchingKeyPrefix keyPrefix: String,
            for operation: PlatformFailure.Operation
        ) throws -> [String] {
            let filter = targetPrefix + escape(keyPrefix) + "*"

            var count: DWORD = 0
            var credentials: UnsafeMutablePointer<PCREDENTIALW?>?
            let enumerated = withWideString(filter) { filter in
                CredEnumerateW(filter, 0, &count, &credentials)
            }

            guard enumerated else {
                // No match at all is reported as a failure with ERROR_NOT_FOUND, not as an empty
                // set, so it has to be translated back into one.
                if GetLastError() == ERROR_NOT_FOUND { return [] }
                throw lastError(operation)
            }
            guard let credentials else { return [] }
            defer { CredFree(credentials) }

            let expectedPrefix = targetPrefix + escape(keyPrefix)
            var names: [String] = []
            for index in 0..<Int(count) {
                guard let credential = credentials[index],
                    let targetName = credential.pointee.TargetName
                else { continue }
                let name = String(decodingCString: targetName, as: UTF16.self)
                guard name.hasPrefix(expectedPrefix) else { continue }
                names.append(name)
            }
            return names
        }
    }

#endif

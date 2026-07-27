// Every platform with a Swift-reachable secure store now has a native backend, so the host
// bridge is what remains for the ones that do not: Android, whose Keystore is Java, and any
// future host in the same position. Backend selection stays compile-time — exactly one backend
// exists per platform, and this is the negative space left by the other three.
#if !canImport(Security) && !os(Windows) && !os(Linux)

    import Foundation
    import Synchronization

    // MARK: - ABI convention
    //
    // Unlike a fire-and-forget bridge, these operations return values and fail, so the C surface
    // has to answer two questions: who owns returned memory, and how does an error travel.
    //
    //   1. NO HEAP POINTERS ARE RETURNED ACROSS THE BOUNDARY. A host that has a result hands it
    //      back by invoking a *sink* callback with a pointer and a length; Swift copies inside
    //      the callback's lifetime and the host frees its buffer as soon as the call returns.
    //      Ownership never crosses, so there is nothing to leak and nothing to free twice.
    //   2. EVERY OPERATION RETURNS AN Int32 STATUS. `SecureStoreStatus.ok` means success;
    //      anything else is surfaced as `SecureStoreError.platform(code:)` carrying the host's
    //      own code, so a failure can be traced to a specific platform error.
    //
    // The sink takes an opaque `context` pointer because `@convention(c)` functions cannot
    // capture — which is precisely the property that makes them safe to hand to JNI.

    /// Status values exchanged with the host. Any value not listed is treated as a host error
    /// and reported verbatim.
    public enum SecureStoreStatus {
        /// The operation succeeded.
        public static let ok: Int32 = 0
        /// The requested item does not exist. Not an error for reads or removals.
        public static let notFound: Int32 = 1
    }

    /// Receives one byte buffer from the host. Valid only for the duration of the call.
    public typealias SecureStoreDataSink =
        @convention(c) (
            _ context: UnsafeMutableRawPointer?, _ bytes: UnsafePointer<UInt8>?, _ length: Int32
        ) -> Void

    /// Receives one key from the host. Valid only for the duration of the call.
    public typealias SecureStoreKeySink =
        @convention(c) (
            _ context: UnsafeMutableRawPointer?, _ key: UnsafePointer<CChar>?
        ) -> Void

    /// The C functions a host installs to service secure storage.
    ///
    /// All take the service and namespace so a single host implementation can serve every store
    /// without Swift holding host-side handles.
    public struct SecureStoreHostCallbacks: Sendable {

        public typealias SetFn =
            @convention(c) (
                _ service: UnsafePointer<CChar>, _ namespace: UnsafePointer<CChar>?,
                _ key: UnsafePointer<CChar>, _ bytes: UnsafePointer<UInt8>, _ length: Int32
            ) -> Int32

        public typealias GetFn =
            @convention(c) (
                _ service: UnsafePointer<CChar>, _ namespace: UnsafePointer<CChar>?,
                _ key: UnsafePointer<CChar>,
                _ context: UnsafeMutableRawPointer?, _ sink: SecureStoreDataSink
            ) -> Int32

        public typealias RemoveFn =
            @convention(c) (
                _ service: UnsafePointer<CChar>, _ namespace: UnsafePointer<CChar>?,
                _ key: UnsafePointer<CChar>
            ) -> Int32

        public typealias RemoveAllFn =
            @convention(c) (
                _ service: UnsafePointer<CChar>, _ namespace: UnsafePointer<CChar>?
            ) -> Int32

        /// Emits every key beginning with `prefix` through the sink. An empty `prefix` means every
        /// key. Hosts whose platform supports prefix filtering natively — Windows Credential
        /// Manager's `CredEnumerateW` takes exactly a name prefix — should push it down rather
        /// than enumerate and discard.
        public typealias KeysFn =
            @convention(c) (
                _ service: UnsafePointer<CChar>, _ namespace: UnsafePointer<CChar>?,
                _ prefix: UnsafePointer<CChar>,
                _ context: UnsafeMutableRawPointer?, _ sink: SecureStoreKeySink
            ) -> Int32

        public let set: SetFn
        public let get: GetFn
        public let remove: RemoveFn
        public let removeAll: RemoveAllFn
        public let keys: KeysFn

        public init(
            set: @escaping SetFn,
            get: @escaping GetFn,
            remove: @escaping RemoveFn,
            removeAll: @escaping RemoveAllFn,
            keys: @escaping KeysFn
        ) {
            self.set = set
            self.get = get
            self.remove = remove
            self.removeAll = removeAll
            self.keys = keys
        }
    }

    // MARK: - Registry

    /// Holds the host's callbacks. Registration lands on the host's startup thread while store
    /// operations arrive from arbitrary Swift concurrency contexts, so it is mutex-guarded.
    ///
    /// Intentionally duplicated rather than shared with other host bridges: at this size the
    /// coupling costs more than the twenty lines. The *conventions* are the thing worth sharing,
    /// and they live in the design doc.
    private let registeredCallbacks = Mutex<SecureStoreHostCallbacks?>(nil)

    /// Installs the host's secure-store implementation. Call once, before any store is used.
    public func registerSecureStoreHost(_ callbacks: SecureStoreHostCallbacks) {
        registeredCallbacks.withLock { $0 = callbacks }
    }

    /// C entry point a JNI shim calls to install the host implementation.
    @_cdecl("securestore_register_host")
    public func securestoreRegisterHost(
        _ set: @escaping SecureStoreHostCallbacks.SetFn,
        _ get: @escaping SecureStoreHostCallbacks.GetFn,
        _ remove: @escaping SecureStoreHostCallbacks.RemoveFn,
        _ removeAll: @escaping SecureStoreHostCallbacks.RemoveAllFn,
        _ keys: @escaping SecureStoreHostCallbacks.KeysFn
    ) {
        registerSecureStoreHost(
            SecureStoreHostCallbacks(
                set: set,
                get: get,
                remove: remove,
                removeAll: removeAll,
                keys: keys
            )
        )
    }

    // MARK: - Store

    /// `SecureStore` backed by host-registered C callbacks.
    ///
    /// Throws `.backendNotRegistered` until the host registers, rather than silently succeeding —
    /// a store that appears to work but persists nothing is far worse than a loud failure.
    public struct HostSecureStore: SecureStore {

        private let configuration: SecureStoreConfiguration

        public init(_ configuration: SecureStoreConfiguration) {
            self.configuration = configuration
        }

        public init(service: String, namespace: String? = nil) {
            self.init(SecureStoreConfiguration(service: service, namespace: namespace))
        }

        private func callbacks() throws -> SecureStoreHostCallbacks {
            guard let callbacks = registeredCallbacks.withLock({ $0 }) else {
                throw SecureStoreError.backendNotRegistered
            }
            return callbacks
        }

        /// Runs `body` with the service and namespace as C strings.
        private func withIdentity<Result>(
            _ body: (UnsafePointer<CChar>, UnsafePointer<CChar>?) throws -> Result
        ) rethrows -> Result {
            try configuration.service.withCString { service in
                guard let namespace = configuration.namespace else {
                    return try body(service, nil)
                }
                return try namespace.withCString { try body(service, $0) }
            }
        }

        private func check(_ status: Int32) throws {
            guard status == SecureStoreStatus.ok else {
                throw SecureStoreError.platform(code: status)
            }
        }

        // MARK: - SecureStore

        public func set(_ data: Data, for key: String) throws {
            let host = try callbacks()
            let status = withIdentity { service, namespace in
                key.withCString { key in
                    data.withUnsafeBytes { buffer -> Int32 in
                        guard let bytes = buffer.bindMemory(to: UInt8.self).baseAddress else {
                            // An empty `Data` has no base address, but the C signature still
                            // requires a non-null pointer. Point at a stack byte and pass length
                            // 0 — the host must not read it. Storing an empty value has to stay
                            // possible: it is distinct from storing nothing.
                            let placeholder: UInt8 = 0
                            return withUnsafePointer(to: placeholder) {
                                host.set(service, namespace, key, $0, 0)
                            }
                        }
                        return host.set(service, namespace, key, bytes, Int32(data.count))
                    }
                }
            }
            try check(status)
        }

        public func data(for key: String) throws -> Data? {
            let host = try callbacks()
            var captured: Data?
            let status = withIdentity { service, namespace in
                key.withCString { key in
                    withUnsafeMutablePointer(to: &captured) { context in
                        host.get(service, namespace, key, UnsafeMutableRawPointer(context)) { context, bytes, length in
                            guard let context else { return }
                            let target = context.assumingMemoryBound(to: Data?.self)
                            // The sink is only invoked for an item that EXISTS — a missing item
                            // is reported by the status code, never by calling back. So a
                            // zero-length call means "stored, and empty", which must produce an
                            // empty `Data` rather than leaving `nil` behind and masquerading as
                            // missing. (An earlier `length > 0` guard did exactly that; the
                            // Android emulator run caught it.)
                            guard let bytes, length > 0 else {
                                target.pointee = Data()
                                return
                            }
                            target.pointee = Data(bytes: bytes, count: Int(length))
                        }
                    }
                }
            }
            if status == SecureStoreStatus.notFound { return nil }
            try check(status)
            return captured
        }

        public func remove(_ key: String) throws {
            let host = try callbacks()
            let status = withIdentity { service, namespace in
                key.withCString { host.remove(service, namespace, $0) }
            }
            // Absent is the caller's desired end state, matching the Apple backend.
            if status == SecureStoreStatus.notFound { return }
            try check(status)
        }

        public func removeAll() throws {
            let host = try callbacks()
            let status = withIdentity { host.removeAll($0, $1) }
            if status == SecureStoreStatus.notFound { return }
            try check(status)
        }

        public func keys(withPrefix prefix: String) throws -> [String] {
            let host = try callbacks()
            var captured: [String] = []
            let status = withIdentity { service, namespace in
                prefix.withCString { prefix in
                    withUnsafeMutablePointer(to: &captured) { context in
                        host.keys(service, namespace, prefix, UnsafeMutableRawPointer(context)) { context, key in
                            guard let context, let key else { return }
                            context.assumingMemoryBound(to: [String].self).pointee.append(String(cString: key))
                        }
                    }
                }
            }
            if status == SecureStoreStatus.notFound { return [] }
            try check(status)
            return captured
        }
    }

#endif

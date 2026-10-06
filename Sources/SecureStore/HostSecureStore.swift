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
    //      anything else is surfaced as `SecureStoreError.platform` carrying the host's own
    //      code, so a failure can be traced to a specific platform error. A host that also
    //      registers a describer (see `securestore_register_host_describer`) gets its own text
    //      carried alongside the code.
    //
    // The sink takes an opaque `context` pointer because `@convention(c)` functions cannot
    // capture — which is precisely the property that makes them safe to hand to JNI.
    //
    // Three things the signatures alone do not say, all specified in
    // docs/design/host-bridge-abi.md and declared for C in docs/design/securestore_host.h:
    //
    //   - STRINGS ARE STANDARD UTF-8, NUL-terminated, in both directions. That is not JNI's
    //     "Modified UTF-8", so `NewStringUTF`/`GetStringUTFChars` are the wrong conversions.
    //   - CALLBACKS RUN ON THE CALLING SWIFT THREAD, synchronously, and that thread is not
    //     necessarily attached to the JVM.
    //   - FUNCTION POINTERS ARE NEVER NULL. They are non-optional here, so a NULL from C is
    //     undefined behaviour rather than a detectable error. Only `namespace`, and the
    //     pointers handed to sinks, may be NULL.

    /// Status values exchanged with the host. Any value not listed is treated as a host error
    /// and reported verbatim.
    public enum SecureStoreStatus {
        /// The operation succeeded.
        public static let ok: Int32 = 0
        /// The requested item does not exist. Not an error for reads or removals.
        public static let notFound: Int32 = 1
    }

    /// Receives one byte buffer from the host. Valid only for the duration of the call.
    ///
    /// `bytes` may be NULL only when `length` is `0`, which reports a stored, empty value. A
    /// negative `length`, or NULL `bytes` with a positive one, cannot describe a value and makes
    /// the read throw `SecureStoreError.invalidData`.
    public typealias SecureStoreDataSink =
        @convention(c) (
            _ context: UnsafeMutableRawPointer?, _ bytes: UnsafePointer<UInt8>?, _ length: Int32
        ) -> Void

    /// Receives one key from the host, as NUL-terminated UTF-8. Valid only for the duration of
    /// the call. A NULL `key` is ignored.
    public typealias SecureStoreKeySink =
        @convention(c) (
            _ context: UnsafeMutableRawPointer?, _ key: UnsafePointer<CChar>?
        ) -> Void

    /// Receives a human-readable description of a status code, as NUL-terminated UTF-8. Valid
    /// only for the duration of the call. A NULL `message` is ignored.
    ///
    /// Structurally identical to `SecureStoreKeySink`, and deliberately a separate name: the two
    /// carry different things, and a host reading the header should not have to infer which from
    /// the parameter position.
    public typealias SecureStoreMessageSink =
        @convention(c) (
            _ context: UnsafeMutableRawPointer?, _ message: UnsafePointer<CChar>?
        ) -> Void

    /// Turns one of the host's own status codes into a message, through the sink.
    ///
    /// Optional. A host that does not register one still reports failures — they simply carry a
    /// number and no text, which is what every host did before this existed.
    public typealias SecureStoreHostDescriber =
        @convention(c) (
            _ status: Int32, _ context: UnsafeMutableRawPointer?, _ sink: SecureStoreMessageSink
        ) -> Void

    /// The C functions a host installs to service secure storage.
    ///
    /// All take the service and namespace so a single host implementation can serve every store
    /// without Swift holding host-side handles.
    ///
    /// Every string is NUL-terminated standard UTF-8 and is valid only for the duration of the
    /// call. `service`, `key` and `prefix` are never NULL; `namespace` is NULL when the store
    /// has none. Each function returns a `SecureStoreStatus` value or the host's own error code.
    public struct SecureStoreHostCallbacks: Sendable {

        /// Stores `length` bytes under `key`, replacing any existing value.
        ///
        /// `bytes` is never NULL, but when `length` is `0` it points at nothing readable — an
        /// empty value is still a value, and must be stored as one. The host must copy what it
        /// needs before returning.
        public typealias SetFn =
            @convention(c) (
                _ service: UnsafePointer<CChar>, _ namespace: UnsafePointer<CChar>?,
                _ key: UnsafePointer<CChar>, _ bytes: UnsafePointer<UInt8>, _ length: Int32
            ) -> Int32

        /// Reads the value stored under `key`.
        ///
        /// For an item that exists, the host calls `sink` exactly once with the bytes, passing
        /// `context` through untouched, and returns `SecureStoreStatus.ok`. For one that does
        /// not, it returns `SecureStoreStatus.notFound` without calling `sink`. Returning `ok`
        /// without having called `sink` is a host bug, reported as
        /// `SecureStoreError.invalidData` rather than as a missing item.
        public typealias GetFn =
            @convention(c) (
                _ service: UnsafePointer<CChar>, _ namespace: UnsafePointer<CChar>?,
                _ key: UnsafePointer<CChar>,
                _ context: UnsafeMutableRawPointer?, _ sink: SecureStoreDataSink
            ) -> Int32

        /// Removes the item stored under `key`. `SecureStoreStatus.notFound` is not an error.
        public typealias RemoveFn =
            @convention(c) (
                _ service: UnsafePointer<CChar>, _ namespace: UnsafePointer<CChar>?,
                _ key: UnsafePointer<CChar>
            ) -> Int32

        /// Removes every item in the given service and namespace.
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

        /// Services `SecureStore.set(_:for:)`.
        public let set: SetFn
        /// Services `SecureStore.data(for:)`.
        public let get: GetFn
        /// Services `SecureStore.remove(_:)`.
        public let remove: RemoveFn
        /// Services `SecureStore.removeAll()`.
        public let removeAll: RemoveAllFn
        /// Services `SecureStore.keys(withPrefix:)`.
        public let keys: KeysFn

        /// Bundles the five host functions. All five are required: a host that cannot support
        /// an operation should install a function that returns an error status, so the failure
        /// is reported rather than crashing on a missing pointer.
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

    /// Holds the host's optional describer. Separate from the callback table so that
    /// registering one is genuinely additive: a host built against the older ABI links and runs
    /// unchanged, and simply reports failures without text.
    private let registeredDescriber = Mutex<SecureStoreHostDescriber?>(nil)

    /// Installs a translator from the host's status codes to human-readable messages.
    ///
    /// Optional, and independent of `registerSecureStoreHost` — call it or don't. Without it a
    /// host failure carries only a number, which is meaningful to whoever wrote the host and
    /// opaque to everyone else reading a bug report.
    public func registerSecureStoreHostDescriber(_ describer: @escaping SecureStoreHostDescriber) {
        registeredDescriber.withLock { $0 = describer }
    }

    /// C entry point a JNI shim calls to install the describer.
    ///
    /// `describer` must not be NULL: the parameter is non-optional, so a NULL from C is
    /// undefined behaviour. A host with nothing to describe simply never calls this.
    ///
    /// Added after `securestore_register_host`, as a *new* symbol rather than a parameter on the
    /// existing one: changing that signature would break every host already compiled against it.
    @_cdecl("securestore_register_host_describer")
    public func securestoreRegisterHostDescriber(_ describer: @escaping SecureStoreHostDescriber) {
        registerSecureStoreHostDescriber(describer)
    }

    /// Asks the registered describer what `status` means, or `nil` if none is registered.
    private func hostMessage(for status: Int32) -> String? {
        guard let describer = registeredDescriber.withLock({ $0 }) else { return nil }
        var captured: String?
        withUnsafeMutablePointer(to: &captured) { context in
            describer(status, UnsafeMutableRawPointer(context)) { context, message in
                guard let context, let message else { return }
                context.assumingMemoryBound(to: String?.self).pointee = String(cString: message)
            }
        }
        return captured
    }

    /// Wraps a host status as a `SecureStoreError`, with the host's own text where available.
    private func hostFailure(_ status: Int32, _ operation: PlatformFailure.Operation)
        -> SecureStoreError
    {
        .platform(
            PlatformFailure(
                backend: .host,
                operation: operation,
                code: status,
                message: hostMessage(for: status)
            )
        )
    }

    /// C entry point a JNI shim calls to install the host implementation.
    ///
    /// None of the five pointers may be NULL: the parameters are non-optional, so a NULL from C
    /// is undefined behaviour rather than an error this function could report. Declared for C
    /// in `docs/design/securestore_host.h`.
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

    /// What the data sink observed during one `get`, carried through the `context` pointer.
    ///
    /// The sink is a non-capturing C function, so it cannot throw or return anything: whatever
    /// it learns has to be written here and judged after the host call returns. `data` staying
    /// `nil` means the sink never ran, which is not the same thing as the item being absent —
    /// absence is the host's `notFound` status.
    private struct HostReadResult {
        var data: Data?
        var malformed = false
    }

    /// The length of a value as the C ABI carries it, or a thrown failure if it does not fit.
    ///
    /// The `set` callback takes an `int32_t` length, while `Data.count` is a 64-bit `Int` on
    /// every platform this backend targets — and `Int32(_:)` traps rather than truncating, so
    /// without this check a value past 2 GiB would crash the process instead of failing the
    /// write. Widening the parameter is not an option: it would change an existing C signature.
    ///
    /// The failure carries code `0` because no host status exists for it — the host was never
    /// called. `0` is the one value a host can never report as a failure, so it cannot be
    /// mistaken for one of the host's own codes; the message says what happened.
    func hostValueLength(_ count: Int) throws -> Int32 {
        guard let length = Int32(exactly: count) else {
            throw SecureStoreError.platform(
                PlatformFailure(
                    backend: .host,
                    operation: .set,
                    code: 0,
                    message: "Value is \(count) bytes; the host bridge cannot carry more than \(Int32.max)"
                )
            )
        }
        return length
    }

    /// The backend `SecureStore` resolves to on this platform. See ``HostSecureStore``.
    ///
    /// Each backend file defines this under its own compile-time gate. The four gates are
    /// mutually exclusive and exhaustive, so exactly one definition exists in any build.
    public typealias PlatformSecureStore = HostSecureStore

    /// `SecureStore` backed by host-registered C callbacks.
    ///
    /// Throws `.backendNotRegistered` until the host registers, rather than silently succeeding —
    /// a store that appears to work but persists nothing is far worse than a loud failure.
    public struct HostSecureStore: SecureStore {

        private let configuration: SecureStoreConfiguration

        /// Creates a store over the items identified by `configuration`.
        ///
        /// Does not require the host to have registered yet — registration is checked on each
        /// operation, so a store may be constructed before `securestore_register_host` runs.
        public init(_ configuration: SecureStoreConfiguration) {
            self.configuration = configuration
        }

        /// Creates a store for `service`, optionally scoped to `namespace`.
        ///
        /// Both are passed to the host verbatim on every call. A host with no notion of a
        /// sharing scope may ignore `namespace`.
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

        private func check(_ status: Int32, _ operation: PlatformFailure.Operation) throws {
            guard status == SecureStoreStatus.ok else {
                throw hostFailure(status, operation)
            }
        }

        // MARK: - SecureStore

        public func set(_ data: Data, for key: String) throws {
            let host = try callbacks()
            let length = try hostValueLength(data.count)
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
                        return host.set(service, namespace, key, bytes, length)
                    }
                }
            }
            try check(status, .set)
        }

        public func data(for key: String) throws -> Data? {
            let host = try callbacks()
            var result = HostReadResult()
            let status = withIdentity { service, namespace in
                key.withCString { key in
                    withUnsafeMutablePointer(to: &result) { context in
                        host.get(service, namespace, key, UnsafeMutableRawPointer(context)) { context, bytes, length in
                            guard let context else { return }
                            let target = context.assumingMemoryBound(to: HostReadResult.self)
                            // A negative length describes no value at all. Reading it as empty
                            // would turn a host bug into a plausible stored credential.
                            guard length >= 0 else {
                                target.pointee.malformed = true
                                return
                            }
                            // The sink is only invoked for an item that EXISTS — a missing item
                            // is reported by the status code, never by calling back. So a
                            // zero-length call means "stored, and empty", which must produce an
                            // empty `Data` rather than leaving `nil` behind and masquerading as
                            // missing. (An earlier `length > 0` guard did exactly that; the
                            // Android emulator run caught it.)
                            guard length > 0 else {
                                target.pointee.data = Data()
                                return
                            }
                            // A null buffer alongside a non-zero length is the same corruption
                            // the Windows and Linux backends refuse to report as empty.
                            guard let bytes else {
                                target.pointee.malformed = true
                                return
                            }
                            target.pointee.data = Data(bytes: bytes, count: Int(length))
                        }
                    }
                }
            }
            if status == SecureStoreStatus.notFound { return nil }
            try check(status, .read)

            // The host said the item exists, so the sink must have delivered it. Returning
            // `nil` here instead would report a host that forgot to call back — or that failed
            // inside its own lookup and still returned 0 — as a missing item: the signed-out
            // user this package exists to prevent.
            guard !result.malformed, let data = result.data else {
                throw SecureStoreError.invalidData
            }
            return data
        }

        public func remove(_ key: String) throws {
            let host = try callbacks()
            let status = withIdentity { service, namespace in
                key.withCString { host.remove(service, namespace, $0) }
            }
            // Absent is the caller's desired end state, matching every native backend.
            if status == SecureStoreStatus.notFound { return }
            try check(status, .remove)
        }

        public func removeAll() throws {
            let host = try callbacks()
            let status = withIdentity { host.removeAll($0, $1) }
            if status == SecureStoreStatus.notFound { return }
            try check(status, .removeAll)
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
            try check(status, .listKeys)
            return captured
        }
    }

#endif

//
//  HostBackendFixture.swift
//  SecureStoreTests
//
//  An in-memory host backend wired through the real C entry point, so the contract suite on
//  non-Apple platforms exercises the actual ABI — the sink callbacks, the status codes, and the
//  service/namespace threading — rather than a Swift stand-in that bypasses all of it.
//
//  Everything is file-scope because `@convention(c)` functions cannot capture context. That
//  constraint is the point: it is what makes these pointers safe to hand to JNI.
//

#if !canImport(Security)

    import Foundation
    import Synchronization

    @testable import SecureStore

    /// `service|namespace` -> key -> value.
    private let storage = Mutex<[String: [String: Data]]>([:])

    private func scope(_ service: UnsafePointer<CChar>, _ namespace: UnsafePointer<CChar>?) -> String {
        let service = String(cString: service)
        guard let namespace else { return service + "|" }
        return service + "|" + String(cString: namespace)
    }

    private let hostSet: SecureStoreHostCallbacks.SetFn = { service, namespace, key, bytes, length in
        let scopeKey = scope(service, namespace)
        let itemKey = String(cString: key)
        let value = Data(bytes: bytes, count: Int(length))
        storage.withLock { $0[scopeKey, default: [:]][itemKey] = value }
        return SecureStoreStatus.ok
    }

    private let hostGet: SecureStoreHostCallbacks.GetFn = { service, namespace, key, context, sink in
        let scopeKey = scope(service, namespace)
        let itemKey = String(cString: key)
        guard let value = storage.withLock({ $0[scopeKey]?[itemKey] }) else {
            return SecureStoreStatus.notFound
        }
        // Hand the bytes back through the sink and let Swift copy — the host keeps ownership,
        // exactly as the ABI convention requires.
        value.withUnsafeBytes { buffer in
            let base = buffer.bindMemory(to: UInt8.self).baseAddress
            sink(context, base, Int32(value.count))
        }
        return SecureStoreStatus.ok
    }

    private let hostRemove: SecureStoreHostCallbacks.RemoveFn = { service, namespace, key in
        let scopeKey = scope(service, namespace)
        let itemKey = String(cString: key)
        let existed = storage.withLock { $0[scopeKey]?.removeValue(forKey: itemKey) != nil }
        return existed ? SecureStoreStatus.ok : SecureStoreStatus.notFound
    }

    private let hostRemoveAll: SecureStoreHostCallbacks.RemoveAllFn = { service, namespace in
        storage.withLock { $0[scope(service, namespace)] = nil }
        return SecureStoreStatus.ok
    }

    private let hostKeys: SecureStoreHostCallbacks.KeysFn = { service, namespace, prefix, context, sink in
        let prefix = String(cString: prefix)
        let keys = storage.withLock { Array(($0[scope(service, namespace)] ?? [:]).keys) }
        // Filtered host-side, mirroring what a real host does — Windows pushes the prefix into
        // `CredEnumerateW`, Android filters its own enumeration — so the suite exercises the
        // contract rather than a Swift-side filter the ABI never sees.
        for key in keys where prefix.isEmpty || key.hasPrefix(prefix) {
            key.withCString { sink(context, $0) }
        }
        return SecureStoreStatus.ok
    }

    enum HostBackendFixture {

        /// Registers the fixture through the public C entry point. Idempotent.
        static func install() {
            securestoreRegisterHost(hostSet, hostGet, hostRemove, hostRemoveAll, hostKeys)
        }

        static func reset() {
            storage.withLock { $0.removeAll() }
        }
    }

#endif

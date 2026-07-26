//
//  SecureStoreContractTests.swift
//  SecureStoreTests
//
//  The behavioural contract every `SecureStore` must satisfy, written once and run against
//  whichever backend the platform provides. Deliberately NOT platform-guarded: the point of this
//  package is that Apple and Android behave the same, and the only way to hold that line is to
//  run one body of assertions against both.
//
//  Apple runs it against the real Keychain. Hosts without Keychain Services run it against an
//  in-memory host backend registered by `HostBackendFixture`, which also exercises the C ABI.
//

import Foundation
import Testing

@testable import SecureStore

@Suite("SecureStore contract", .serialized)
struct SecureStoreContractTests {

    /// A store scoped to this test run, so a failure cannot leave residue in a developer's real
    /// keychain and concurrent runs cannot collide.
    private func makeStore(_ label: String) throws -> any SecureStore {
        let service = "dev.securestore.tests.\(label).\(UUID().uuidString)"
        #if canImport(Security)
            return KeychainSecureStore(service: service)
        #else
            HostBackendFixture.install()
            return HostSecureStore(service: service)
        #endif
    }

    @Test("A stored value reads back byte-for-byte")
    func roundTrip() throws {
        let store = try makeStore("round-trip")
        defer { try? store.removeAll() }

        let payload = Data("session-token-\u{1F511}".utf8)
        try store.set(payload, for: "session")

        #expect(try store.data(for: "session") == payload)
    }

    @Test("A missing key reads as nil, not as an error")
    func missingKeyIsNil() throws {
        let store = try makeStore("missing")
        defer { try? store.removeAll() }

        #expect(try store.data(for: "never-written") == nil)
    }

    @Test("Writing the same key twice replaces rather than duplicates")
    func overwriteReplaces() throws {
        let store = try makeStore("overwrite")
        defer { try? store.removeAll() }

        try store.set(Data("first".utf8), for: "token")
        try store.set(Data("second".utf8), for: "token")

        #expect(try store.data(for: "token") == Data("second".utf8))
        #expect(try store.allKeys() == ["token"])
    }

    @Test("Removing a key deletes only that key")
    func removeIsScoped() throws {
        let store = try makeStore("remove")
        defer { try? store.removeAll() }

        try store.set(Data("a".utf8), for: "keep")
        try store.set(Data("b".utf8), for: "drop")
        try store.remove("drop")

        #expect(try store.data(for: "drop") == nil)
        #expect(try store.data(for: "keep") == Data("a".utf8))
    }

    @Test("Removing a key that was never stored is not an error")
    func removeMissingIsNotAnError() throws {
        let store = try makeStore("remove-missing")
        defer { try? store.removeAll() }

        try store.remove("never-written")
    }

    @Test("removeAll empties the store")
    func removeAllEmpties() throws {
        let store = try makeStore("remove-all")
        defer { try? store.removeAll() }

        try store.set(Data("a".utf8), for: "one")
        try store.set(Data("b".utf8), for: "two")
        try store.removeAll()

        #expect(try store.allKeys().isEmpty)
        #expect(try store.data(for: "one") == nil)
    }

    @Test("allKeys reports every stored key and nothing else")
    func allKeysReportsStoredKeys() throws {
        let store = try makeStore("all-keys")
        defer { try? store.removeAll() }

        #expect(try store.allKeys().isEmpty)

        try store.set(Data("a".utf8), for: "alpha")
        try store.set(Data("b".utf8), for: "beta")

        #expect(Set(try store.allKeys()) == ["alpha", "beta"])
    }

    @Test("Two stores with different services do not see each other's items")
    func servicesAreIsolated() throws {
        let first = try makeStore("isolation-a")
        let second = try makeStore("isolation-b")
        defer {
            try? first.removeAll()
            try? second.removeAll()
        }

        try first.set(Data("secret".utf8), for: "shared-key-name")

        #expect(try second.data(for: "shared-key-name") == nil)
        #expect(try second.allKeys().isEmpty)
    }

    @Test("Binary payloads survive intact, including NUL bytes")
    func binarySafe() throws {
        let store = try makeStore("binary")
        defer { try? store.removeAll() }

        let payload = Data([0x00, 0xFF, 0x10, 0x00, 0x7F])
        try store.set(payload, for: "blob")

        #expect(try store.data(for: "blob") == payload)
    }

    @Test("An empty value is stored and read back as empty, not as missing")
    func emptyValueRoundTrips() throws {
        let store = try makeStore("empty")
        defer { try? store.removeAll() }

        try store.set(Data(), for: "empty")

        // Distinguishing "stored, empty" from "absent" is why this is asserted explicitly:
        // the zero-length buffer is also the case where `baseAddress` is nil on the host path.
        #expect(try store.allKeys() == ["empty"])
        #expect(try store.data(for: "empty")?.isEmpty == true)
    }
}

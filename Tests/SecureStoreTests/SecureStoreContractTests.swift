//
//  SecureStoreContractTests.swift
//  SecureStoreTests
//
//  The behavioural contract every `SecureStore` must satisfy, written once and run against
//  whichever backend the platform provides. Deliberately NOT platform-guarded: the point of this
//  package is that all four backends behave the same, and the only way to hold that line is to
//  run one body of assertions against every one of them.
//
//  Apple runs it against the real Keychain, Windows against the real Credential Manager, and
//  Linux against a real Secret Service provider. Android — the one platform whose secure store
//  is not reachable from Swift — runs it against an in-memory host backend registered by
//  `HostBackendFixture`, which also exercises the C ABI.
//

import Foundation
import Testing

@testable import SecureStore

/// Empties `store` after a test.
///
/// `defer` cannot throw, but discarding the error with `try?` is not an option — swallowing a
/// failure is exactly the behaviour this package is built to prevent, so a cleanup failure is
/// recorded as a test issue instead. Shared with the backend-specific suites for the same
/// reason.
func cleanUp(
    _ store: any SecureStore,
    sourceLocation: SourceLocation = #_sourceLocation
) {
    do {
        try store.removeAll()
    } catch {
        Issue.record("SecureStore cleanup failed: \(error)", sourceLocation: sourceLocation)
    }
}

@Suite("SecureStore contract", .serialized)
struct SecureStoreContractTests {

    /// A store scoped to this test run, so a failure cannot leave residue in a developer's real
    /// keychain and concurrent runs cannot collide.
    private func makeStore(_ label: String) throws -> any SecureStore {
        try makeStore(service: uniqueService(label))
    }

    /// A service name no other test, and no other run, will produce.
    private func uniqueService(_ label: String) -> String {
        "dev.securestore.tests.\(label).\(UUID().uuidString)"
    }

    /// A store for exactly this service and namespace, for the tests that need two stores
    /// related to each other in a specific way. `service` must come from `uniqueService`.
    private func makeStore(service: String, namespace: String? = nil) throws -> any SecureStore {
        // One branch per backend, mirroring the compile-time selection in Sources. Adding a
        // backend without adding it here would leave it unasserted, which is the one thing this
        // suite exists to prevent.
        #if canImport(Security)
            return KeychainSecureStore(service: service, namespace: namespace)
        #elseif os(Windows)
            return WindowsSecureStore(service: service, namespace: namespace)
        #elseif os(Linux)
            return LinuxSecureStore(service: service, namespace: namespace)
        #else
            HostBackendFixture.install()
            return HostSecureStore(service: service, namespace: namespace)
        #endif
    }

    @Test("A stored value reads back byte-for-byte")
    func roundTrip() throws {
        let store = try makeStore("round-trip")
        defer { cleanUp(store) }

        let payload = Data("session-token-\u{1F511}".utf8)
        try store.set(payload, for: "session")

        #expect(try store.data(for: "session") == payload)
    }

    @Test("A missing key reads as nil, not as an error")
    func missingKeyIsNil() throws {
        let store = try makeStore("missing")
        defer { cleanUp(store) }

        #expect(try store.data(for: "never-written") == nil)
    }

    @Test("Writing the same key twice replaces rather than duplicates")
    func overwriteReplaces() throws {
        let store = try makeStore("overwrite")
        defer { cleanUp(store) }

        try store.set(Data("first".utf8), for: "token")
        try store.set(Data("second".utf8), for: "token")

        #expect(try store.data(for: "token") == Data("second".utf8))
        #expect(try store.allKeys() == ["token"])
    }

    @Test("Removing a key deletes only that key")
    func removeIsScoped() throws {
        let store = try makeStore("remove")
        defer { cleanUp(store) }

        try store.set(Data("a".utf8), for: "keep")
        try store.set(Data("b".utf8), for: "drop")
        try store.remove("drop")

        #expect(try store.data(for: "drop") == nil)
        #expect(try store.data(for: "keep") == Data("a".utf8))
    }

    @Test("Removing a key that was never stored is not an error")
    func removeMissingIsNotAnError() throws {
        let store = try makeStore("remove-missing")
        defer { cleanUp(store) }

        try store.remove("never-written")
    }

    @Test("removeAll empties the store")
    func removeAllEmpties() throws {
        let store = try makeStore("remove-all")
        defer { cleanUp(store) }

        try store.set(Data("a".utf8), for: "one")
        try store.set(Data("b".utf8), for: "two")
        try store.removeAll()

        #expect(try store.allKeys().isEmpty)
        #expect(try store.data(for: "one") == nil)
    }

    @Test("allKeys reports every stored key and nothing else")
    func allKeysReportsStoredKeys() throws {
        let store = try makeStore("all-keys")
        defer { cleanUp(store) }

        #expect(try store.allKeys().isEmpty)

        try store.set(Data("a".utf8), for: "alpha")
        try store.set(Data("b".utf8), for: "beta")

        #expect(Set(try store.allKeys()) == ["alpha", "beta"])
    }

    @Test("keys(withPrefix:) returns only matching keys")
    func prefixFiltersKeys() throws {
        let store = try makeStore("prefix")
        defer { cleanUp(store) }

        try store.set(Data("a".utf8), for: "session.alice")
        try store.set(Data("b".utf8), for: "session.bob")
        try store.set(Data("c".utf8), for: "oauth.alice")

        #expect(Set(try store.keys(withPrefix: "session.")) == ["session.alice", "session.bob"])
        #expect(try store.keys(withPrefix: "oauth.") == ["oauth.alice"])
    }

    @Test("An empty prefix returns every key, so allKeys is a special case of it")
    func emptyPrefixReturnsEverything() throws {
        let store = try makeStore("prefix-empty")
        defer { cleanUp(store) }

        try store.set(Data("a".utf8), for: "one")
        try store.set(Data("b".utf8), for: "two")

        #expect(Set(try store.keys(withPrefix: "")) == Set(try store.allKeys()))
        #expect(Set(try store.keys(withPrefix: "")) == ["one", "two"])
    }

    @Test("A prefix matching nothing returns empty, not an error")
    func unmatchedPrefixIsEmpty() throws {
        let store = try makeStore("prefix-miss")
        defer { cleanUp(store) }

        try store.set(Data("a".utf8), for: "session.alice")

        #expect(try store.keys(withPrefix: "nope.").isEmpty)
    }

    @Test("Prefix matching is exact, not fuzzy — a key equal to the prefix matches")
    func prefixIsLiteral() throws {
        let store = try makeStore("prefix-literal")
        defer { cleanUp(store) }

        try store.set(Data("a".utf8), for: "session")
        try store.set(Data("b".utf8), for: "session.alice")
        try store.set(Data("c".utf8), for: "presession")

        // "presession" must NOT match: this is a prefix, not a substring search — which also
        // matches Windows `CredEnumerateW`'s documented "name prefix followed by an asterisk".
        #expect(Set(try store.keys(withPrefix: "session")) == ["session", "session.alice"])
    }

    @Test("Two stores with different services do not see each other's items")
    func servicesAreIsolated() throws {
        let first = try makeStore("isolation-a")
        let second = try makeStore("isolation-b")
        defer {
            cleanUp(first)
            cleanUp(second)
        }

        try first.set(Data("secret".utf8), for: "shared-key-name")

        #expect(try second.data(for: "shared-key-name") == nil)
        #expect(try second.allKeys().isEmpty)
    }

    @Test("Binary payloads survive intact, including NUL bytes")
    func binarySafe() throws {
        let store = try makeStore("binary")
        defer { cleanUp(store) }

        let payload = Data([0x00, 0xFF, 0x10, 0x00, 0x7F])
        try store.set(payload, for: "blob")

        #expect(try store.data(for: "blob") == payload)
    }

    @Test("An empty value is stored and read back as empty, not as missing")
    func emptyValueRoundTrips() throws {
        let store = try makeStore("empty")
        defer { cleanUp(store) }

        try store.set(Data(), for: "empty")

        // Distinguishing "stored, empty" from "absent" is why this is asserted explicitly:
        // the zero-length buffer is also the case where `baseAddress` is nil on the host path.
        #expect(try store.allKeys() == ["empty"])
        #expect(try store.data(for: "empty")?.isEmpty == true)
    }

    // MARK: - Keys that are awkward for some backend

    /// Keys chosen because each is special to at least one backend: `:` and `%` are the
    /// separator and the escape character of a Windows target name, `%3A` and `%25` are what
    /// those escape *to*, `*` is `CredEnumerateW`'s wildcard, and the rest leave ASCII — the
    /// last three beginning with, or putting a separator directly before, a combining mark,
    /// which fuses with whatever precedes it into one user-perceived character.
    private static let awkwardKeys = [
        "a:b", "a%b", "a%3Ab", "a%253Ab", "a*b", "*", ":", "%",
        "ключ", "session-\u{1F511}", "\u{0301}leading-mark", ":\u{0301}colon-mark", "%\u{0301}percent-mark",
    ]

    @Test("Keys containing separators, escapes, wildcards and non-ASCII round-trip and enumerate")
    func awkwardKeysRoundTrip() throws {
        let store = try makeStore("awkward-keys")
        defer { cleanUp(store) }

        for key in Self.awkwardKeys {
            try store.set(Data("value of \(key)".utf8), for: key)
        }

        // Each key reads back its own value: none aliased another, and none was mangled on the
        // way in.
        for key in Self.awkwardKeys {
            #expect(try store.data(for: key) == Data("value of \(key)".utf8), "key: \(key.debugDescription)")
        }
        // Compared by scalars, not with `==`: `String` equality is canonical equivalence, which
        // would let a backend that normalized a key pass as though it had preserved it.
        let listed = Set(try store.allKeys().map { Array($0.unicodeScalars) })
        #expect(listed == Set(Self.awkwardKeys.map { Array($0.unicodeScalars) }))
    }

    @Test("A key beginning with a combining mark is enumerated and removed like any other")
    func leadingCombiningMarkIsNotLost() throws {
        let store = try makeStore("combining-mark")
        defer { cleanUp(store) }

        // On Windows this key fuses with the `:` that ends the store's target-name prefix, so a
        // character-based prefix test concluded the item belonged to some other store: it
        // vanished from `keys()`, and `removeAll()` left it behind in the user's credentials.
        let key = "\u{0301}token"
        try store.set(Data("a".utf8), for: key)
        try store.set(Data("b".utf8), for: "plain")

        #expect(Set(try store.allKeys()) == [key, "plain"])

        try store.removeAll()

        #expect(try store.allKeys().isEmpty)
        #expect(try store.data(for: key) == nil)
    }

    @Test("A wildcard or separator in a prefix is matched literally")
    func prefixSpecialCharactersAreLiteral() throws {
        let store = try makeStore("prefix-special")
        defer { cleanUp(store) }

        for key in ["a*b", "a:b", "a%b", "a%3Ab", "axb"] {
            try store.set(Data(key.utf8), for: key)
        }

        // `*` must not act as a wildcard — "axb" would match if it did.
        #expect(try store.keys(withPrefix: "a*") == ["a*b"])
        #expect(try store.keys(withPrefix: "a:") == ["a:b"])
        // "a:b" is stored on Windows as "a%3Ab"; a prefix of "a%3" must find only the key
        // that really contains those characters.
        #expect(try store.keys(withPrefix: "a%3") == ["a%3Ab"])
        #expect(Set(try store.keys(withPrefix: "a%")) == ["a%b", "a%3Ab"])
    }

    @Test("A separator in a service or key cannot make two stores collide")
    func separatorsDoNotCollide() throws {
        // Windows joins service, namespace and key into one name with `:`. Joined naively,
        // service "x:b" + key "c" and service "x" + key "b:c" are the same name, and one store
        // reads the other's secret.
        let base = uniqueService("collision")
        let first = try makeStore(service: base + ":b")
        let second = try makeStore(service: base)
        defer {
            cleanUp(first)
            cleanUp(second)
        }

        try first.set(Data("first".utf8), for: "c")
        try second.set(Data("second".utf8), for: "b:c")

        #expect(try first.data(for: "c") == Data("first".utf8))
        #expect(try second.data(for: "b:c") == Data("second".utf8))
        #expect(try first.allKeys() == ["c"])
        #expect(try second.allKeys() == ["b:c"])
    }

    // MARK: - Namespace

    // Asserted only where the backend scopes items by namespace itself. On Apple the namespace
    // is a keychain access group, which the system enforces through code-signing entitlements
    // that a `swift test` process does not have — and which the macOS file keychain ignores
    // outright — so the same assertions there would either fail or pass for the wrong reason.
    #if !canImport(Security)

        @Test("Two stores with the same service and different namespaces do not see each other's items")
        func namespacesAreIsolated() throws {
            let service = uniqueService("namespace")
            let unscoped = try makeStore(service: service)
            let teamA = try makeStore(service: service, namespace: "team.a")
            let teamB = try makeStore(service: service, namespace: "team.b")
            defer {
                cleanUp(unscoped)
                cleanUp(teamA)
                cleanUp(teamB)
            }

            try unscoped.set(Data("none".utf8), for: "token")
            try teamA.set(Data("a".utf8), for: "token")
            try teamB.set(Data("b".utf8), for: "token")
            try teamA.set(Data("only-a".utf8), for: "extra")

            #expect(try unscoped.data(for: "token") == Data("none".utf8))
            #expect(try teamA.data(for: "token") == Data("a".utf8))
            #expect(try teamB.data(for: "token") == Data("b".utf8))
            #expect(try unscoped.data(for: "extra") == nil)
            #expect(try teamB.data(for: "extra") == nil)

            #expect(try unscoped.allKeys() == ["token"])
            #expect(Set(try teamA.allKeys()) == ["token", "extra"])
            #expect(try teamB.allKeys() == ["token"])

            // Emptying one namespace — including the unscoped store, whose "no namespace" must
            // not mean "every namespace" — leaves the others intact.
            try unscoped.removeAll()
            #expect(try unscoped.allKeys().isEmpty)
            #expect(try teamA.data(for: "token") == Data("a".utf8))

            try teamA.removeAll()
            #expect(try teamA.allKeys().isEmpty)
            #expect(try teamB.data(for: "token") == Data("b".utf8))
        }

        @Test("A separator followed by a combining mark cannot make two namespaces collide")
        func combiningMarkSeparatorsDoNotCollide() throws {
            // The Windows escape once skipped a `:` that was followed by a combining mark,
            // because the two form a single character and the search was character-based. That
            // left a raw separator in the name, and these two stores flattened to the same one.
            let service = uniqueService("namespace-collision")
            let first = try makeStore(service: service, namespace: "b:\u{0301}c")
            let second = try makeStore(service: service, namespace: "b")
            defer {
                cleanUp(first)
                cleanUp(second)
            }

            try first.set(Data("first".utf8), for: "\u{0301}k")
            try second.set(Data("second".utf8), for: "\u{0301}c:\u{0301}k")

            #expect(try first.data(for: "\u{0301}k") == Data("first".utf8))
            #expect(try second.data(for: "\u{0301}c:\u{0301}k") == Data("second".utf8))
            #expect(try first.allKeys().count == 1)
            #expect(try second.allKeys().count == 1)
        }

    #endif

    // MARK: - Platform selection

    @Test("PlatformSecureStore names the backend this platform compiles")
    func platformAliasNamesTheBackend() {
        #if canImport(Security)
            #expect(PlatformSecureStore.self == KeychainSecureStore.self)
        #elseif os(Windows)
            #expect(PlatformSecureStore.self == WindowsSecureStore.self)
        #elseif os(Linux)
            #expect(PlatformSecureStore.self == LinuxSecureStore.self)
        #else
            #expect(PlatformSecureStore.self == HostSecureStore.self)
        #endif
    }
}

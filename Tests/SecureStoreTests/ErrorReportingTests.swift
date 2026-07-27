//
//  ErrorReportingTests.swift
//  SecureStoreTests
//
//  A platform failure has to say enough to act on. A bare status code does not: it names
//  neither the store that produced it nor the operation that was in flight, and it discards
//  whatever the platform said about it.
//
//  That is not a theoretical complaint. `LinuxSecureStore` shipped its first CI run reporting
//  `.platform(code: 19)` for every write while reads of absent keys succeeded — which reads as
//  a backend bug. The actual cause was a container with no default Secret Service collection,
//  and libsecret had said so all along: "Object does not exist at path
//  /org/freedesktop/secrets/collection/login". The code threw the message away.
//
//  The rendering tests below are portable. The tests that force a *real* platform failure are
//  necessarily platform-specific, because what reliably fails differs per backend — there is no
//  portable way to make a healthy Keychain refuse a write.
//

import Foundation
import Testing

@testable import SecureStore

@Suite("Platform failure reporting")
struct PlatformFailureTests {

    // MARK: - Rendering (portable)

    @Test("A description names the backend, the operation, and the code")
    func descriptionCarriesContext() {
        let failure = PlatformFailure(backend: .keychain, operation: .set, code: -25299)
        #expect(failure.description == "Keychain Services set failed (code -25299)")
    }

    @Test("A platform message is appended when there is one")
    func descriptionIncludesMessage() {
        let failure = PlatformFailure(
            backend: .credentialManager,
            operation: .read,
            code: 1168,
            message: "Element not found."
        )
        #expect(
            failure.description
                == "Credential Manager read failed (code 1168): Element not found."
        )
    }

    @Test("A domain is rendered alongside the code, since the code alone is ambiguous without it")
    func descriptionIncludesDomain() {
        let failure = PlatformFailure(
            backend: .secretService,
            operation: .set,
            code: 19,
            message: "Object does not exist at path /org/freedesktop/secrets/collection/login",
            domain: "g-io-error-quark"
        )
        #expect(
            failure.description == """
                Secret Service set failed (g-io-error-quark, code 19): \
                Object does not exist at path /org/freedesktop/secrets/collection/login
                """
        )
    }

    @Test("An empty message is treated as no message, not as an empty suffix")
    func emptyMessageIsOmitted() {
        let failure = PlatformFailure(backend: .host, operation: .removeAll, code: 7, message: "")
        #expect(failure.description == "host backend removeAll failed (code 7)")
    }

    @Test("Operations render as prose where the case name would not read")
    func operationNamesRead() {
        let failure = PlatformFailure(backend: .keychain, operation: .listKeys, code: 1)
        #expect(failure.description == "Keychain Services key enumeration failed (code 1)")
    }

    // MARK: - Real failures (platform-specific)

    #if os(Windows)

        @Test("A Credential Manager failure carries the system's own message")
        func windowsFailureCarriesSystemMessage() throws {
            let store = WindowsSecureStore(service: "dev.securestore.tests.error.\(UUID().uuidString)")

            // Credential Manager caps a blob at CRED_MAX_CREDENTIAL_BLOB_SIZE (2,560 bytes).
            // Exceeding it is the one failure this backend can be made to produce on demand
            // without breaking the user's actual credential store.
            let oversized = Data(repeating: 0, count: 8 * 1024)

            do {
                try store.set(oversized, for: "too-big")
                Issue.record("Expected an oversized credential to be rejected")
            } catch let SecureStoreError.platform(failure) {
                #expect(failure.backend == .credentialManager)
                #expect(failure.operation == .set)
                #expect(failure.code != 0)
                // FormatMessageW resolved the code rather than leaving the caller a bare number.
                let message = try #require(failure.message)
                #expect(!message.isEmpty)
            }
        }

    #endif

    #if !canImport(Security) && !os(Windows) && !os(Linux)

        @Test("A host failure carries the message the host's describer produced")
        func hostFailureCarriesDescribedMessage() throws {
            HostBackendFixture.install()
            let store = HostSecureStore(service: "dev.securestore.tests.error.\(UUID().uuidString)")

            do {
                try store.set(Data("x".utf8), for: hostBackendFixtureFailingKey)
                Issue.record("Expected the fixture to fail for its sentinel key")
            } catch let SecureStoreError.platform(failure) {
                #expect(failure.backend == .host)
                #expect(failure.operation == .set)
                #expect(failure.code == hostBackendFixtureFailureStatus)
                // The message travelled back through the real C describer entry point and its
                // sink — not through a Swift shortcut that skips the ABI.
                #expect(failure.message == hostBackendFixtureFailureMessage)
            }
        }

    // There is deliberately no test for the "host registered no describer" path. Asserting
    // it would need a way to clear the registry, and adding one purely for a test would put
    // a footgun in the public API of a credential store — a call that silently degrades
    // every subsequent error. The guarantee is structural instead: the describer lives in
    // its own registry defaulted to nil, behind its own C symbol, so a host built before it
    // existed neither calls it nor links against it.

    #endif
}

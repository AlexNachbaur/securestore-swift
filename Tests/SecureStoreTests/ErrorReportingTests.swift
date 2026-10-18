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

    @Test("Every operation renders under a stable name")
    func operationNamesAreStable() {
        // `removeAll` once spelled its raw value out by hand. It is now implicit, and this is
        // what holds the rendered text still if the case is ever renamed.
        #expect(PlatformFailure.Operation.set.rawValue == "set")
        #expect(PlatformFailure.Operation.read.rawValue == "read")
        #expect(PlatformFailure.Operation.remove.rawValue == "remove")
        #expect(PlatformFailure.Operation.removeAll.rawValue == "removeAll")
        #expect(PlatformFailure.Operation.listKeys.rawValue == "key enumeration")
    }

    // MARK: - localizedDescription (portable)
    //
    // Most logging and alert code reaches for `localizedDescription`, not `description`. Without
    // a `LocalizedError` conformance Foundation answers with "The operation couldn’t be
    // completed" and a type name, which throws away everything the failure carries.

    @Test("localizedDescription carries the failure, whether or not it is wrapped")
    func localizedDescriptionCarriesContext() {
        let failure = PlatformFailure(
            backend: .credentialManager,
            operation: .read,
            code: 1168,
            message: "Element not found."
        )
        let expected = "Credential Manager read failed (code 1168): Element not found."

        #expect(failure.localizedDescription == expected)
        #expect(SecureStoreError.platform(failure).localizedDescription == expected)
        // Through an existential, which is how a `catch` block actually sees it.
        let erased: any Error = SecureStoreError.platform(failure)
        #expect(erased.localizedDescription == expected)
    }

    @Test("The cases with no platform failure still describe themselves")
    func localizedDescriptionCoversEveryCase() {
        let invalidData: any Error = SecureStoreError.invalidData
        let notRegistered: any Error = SecureStoreError.backendNotRegistered

        #expect(
            invalidData.localizedDescription
                == "The secure store returned a value that could not be read back as data"
        )
        #expect(
            notRegistered.localizedDescription
                == "No secure-store backend has been registered by the host"
        )
    }
}

// MARK: - Configuration

@Suite("SecureStoreConfiguration")
struct SecureStoreConfigurationTests {

    /// Credential Manager and the Secret Service must render a namespace into a lookup key, and
    /// both spell "none" as the empty string — so an un-normalized `""` would select the same
    /// items as `nil` there while staying distinct on Apple and the host bridge. Normalizing at
    /// construction is what stops the four backends from disagreeing.
    @Test("An empty namespace is the absence of one, on every backend")
    func emptyNamespaceNormalizesToNil() {
        #expect(SecureStoreConfiguration(service: "s", namespace: "").namespace == nil)
        #expect(SecureStoreConfiguration(service: "s", namespace: nil).namespace == nil)
        #expect(SecureStoreConfiguration(service: "s") == SecureStoreConfiguration(service: "s", namespace: ""))
    }

    @Test("A real namespace is preserved untouched")
    func realNamespaceSurvives() {
        #expect(SecureStoreConfiguration(service: "s", namespace: "team.shared").namespace == "team.shared")
    }

}

// MARK: - Real failures (platform-specific)

// Failures forced out of a real backend, as opposed to the rendering of one built by hand.
//
// Their own suites rather than a section of the configuration tests, where these used to sit: a
// failing run should say that a backend stopped reporting its errors, not that
// `SecureStoreConfiguration` is broken.
//
// There is no Keychain or Secret Service suite, because neither can be made to fail on demand
// without damaging the developer's real store: a healthy keychain accepts any write this
// package can express, and locking a keyring from a test would leave it locked.

#if os(Windows)

    @Suite("Credential Manager failures")
    struct CredentialManagerFailureTests {

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
    }

#endif

#if !canImport(Security) && !os(Windows) && !os(Linux)

    @Suite("Host backend failures")
    struct HostBackendFailureTests {

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
    }

#endif

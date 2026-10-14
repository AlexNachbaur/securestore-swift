//
//  HostBridgeTests.swift
//  SecureStoreTests
//
//  What the host bridge does when the host on the other side of the C boundary gets the
//  contract wrong. The contract suite cannot cover this — it runs against a fixture that behaves
//  — and it is the part that matters most: the host is third-party code, and every one of these
//  mistakes used to come back as a plausible value or a missing item instead of an error.
//

#if !canImport(Security) && !os(Windows) && !os(Linux)

    import Foundation
    import Testing

    @testable import SecureStore

    @Suite("Host bridge: a misbehaving host")
    struct HostBridgeMisbehaviourTests {

        private func makeStore(_ label: String) -> HostSecureStore {
            HostBackendFixture.install()
            return HostSecureStore(service: "dev.securestore.tests.host.\(label).\(UUID().uuidString)")
        }

        /// The failure the package exists to prevent, at the one boundary it does not control:
        /// a host that fails inside its own lookup and still returns `0`, or simply forgets to
        /// call back, must not read as "no such item".
        @Test("Status OK without the sink being called throws, rather than reading as missing")
        func okWithoutSinkIsNotMissing() {
            let store = makeStore("silent-sink")
            #expect(throws: SecureStoreError.invalidData) {
                try store.data(for: hostBackendFixtureSilentSinkKey)
            }
        }

        @Test("A negative length throws, rather than reading as an empty value")
        func negativeLengthIsNotEmpty() {
            let store = makeStore("negative-length")
            #expect(throws: SecureStoreError.invalidData) {
                try store.data(for: hostBackendFixtureNegativeLengthKey)
            }
        }

        @Test("A NULL buffer with a positive length throws, rather than reading as an empty value")
        func nullBufferWithLengthIsNotEmpty() {
            let store = makeStore("null-buffer")
            #expect(throws: SecureStoreError.invalidData) {
                try store.data(for: hostBackendFixtureNullBufferKey)
            }
        }

        /// The ABI says the sink is called exactly once for an item that exists. A host that
        /// calls it twice has lost track of which value it stored; picking the last one would
        /// hand the caller a credential the host never meant to return.
        @Test("Calling the sink twice throws, rather than keeping the last value")
        func doubleSinkIsNotLastWriteWins() {
            let store = makeStore("double-sink")
            #expect(throws: SecureStoreError.invalidData) {
                try store.data(for: hostBackendFixtureDoubleSinkKey)
            }
        }

        /// A missing item still has to be `nil` — the checks above must not have turned every
        /// sink-less return into an error.
        @Test("Not-found without the sink being called is still nil")
        func notFoundIsStillNil() throws {
            let store = makeStore("still-nil")
            #expect(try store.data(for: "never-written") == nil)
        }
    }

    @Suite("Host bridge: value length")
    struct HostBridgeValueLengthTests {

        @Test("A length the ABI can carry passes through unchanged")
        func representableLengths() throws {
            #expect(try hostValueLength(0) == 0)
            #expect(try hostValueLength(2_560) == 2_560)
            #expect(try hostValueLength(Int(Int32.max)) == Int32.max)
        }

        // The oversized case needs an `Int` wider than the ABI's `int32_t` to even express.
        // On a 32-bit target `Data.count` cannot exceed `Int32.max`, so there is nothing to
        // assert there.
        //
        // The check is tested through `hostValueLength` rather than by storing a real 2 GiB
        // value: allocating one on a CI emulator is a good way to have the run killed.
        #if _pointerBitWidth(_64)

            @Test("A value too large for the ABI's int32_t length throws instead of trapping")
            func oversizedLengthThrows() {
                let tooLarge = Int(Int32.max) + 1
                do {
                    _ = try hostValueLength(tooLarge)
                    Issue.record("Expected a length past Int32.max to be rejected")
                } catch let SecureStoreError.platform(failure) {
                    #expect(failure.backend == .host)
                    #expect(failure.operation == .set)
                    // Not a host status: the host was never called. See `hostValueLength`.
                    #expect(failure.code == 0)
                    #expect(failure.message?.contains("\(tooLarge)") == true)
                } catch {
                    Issue.record("Expected SecureStoreError.platform, got \(error)")
                }
            }

        #endif
    }

#endif

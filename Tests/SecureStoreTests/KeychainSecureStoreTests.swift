//
//  KeychainSecureStoreTests.swift
//  SecureStoreTests
//
//  Keychain-specific mechanics only. Behaviour every backend shares belongs in the contract
//  suite; this file covers the one thing that is purely a property of Keychain Services — that
//  a write is two calls, and what happens when another process gets in between them.
//

#if canImport(Security)

    import Foundation
    import Security
    import Testing

    @testable import SecureStore

    @Suite("Keychain add-or-update")
    struct KeychainUpsertTests {

        /// Replays a scripted sequence of statuses and counts how often it was asked.
        private struct Script {
            var statuses: [OSStatus]
            var calls = 0

            mutating func next() -> OSStatus {
                defer { calls += 1 }
                // Running off the end is itself a failure of the test's expectations, and has
                // to be a status no branch of the upsert treats as success or as retryable.
                return calls < statuses.count ? statuses[calls] : errSecInternalError
            }
        }

        @Test("A new item is added and never updated")
        func addSucceeds() {
            var add = Script(statuses: [errSecSuccess])
            var update = Script(statuses: [])

            let status = keychainUpsert(add: { add.next() }, update: { update.next() })

            #expect(status == errSecSuccess)
            #expect(add.calls == 1)
            #expect(update.calls == 0)
        }

        @Test("An existing item is updated")
        func duplicateFallsBackToUpdate() {
            var add = Script(statuses: [errSecDuplicateItem])
            var update = Script(statuses: [errSecSuccess])

            let status = keychainUpsert(add: { add.next() }, update: { update.next() })

            #expect(status == errSecSuccess)
            #expect(add.calls == 1)
            #expect(update.calls == 1)
        }

        /// The race itself: another process deletes the item after the add saw a duplicate and
        /// before the update ran. This used to surface as `errSecItemNotFound` from a write.
        @Test("An item deleted between the add and the update is added again")
        func deleteBetweenAddAndUpdateRetriesTheAdd() {
            var add = Script(statuses: [errSecDuplicateItem, errSecSuccess])
            var update = Script(statuses: [errSecItemNotFound])

            let status = keychainUpsert(add: { add.next() }, update: { update.next() })

            #expect(status == errSecSuccess)
            #expect(add.calls == 2)
            #expect(update.calls == 1)
        }

        @Test("Losing the race twice is reported, not retried forever")
        func retryIsBounded() {
            var add = Script(statuses: [errSecDuplicateItem, errSecDuplicateItem, errSecDuplicateItem])
            var update = Script(statuses: [errSecItemNotFound, errSecItemNotFound, errSecItemNotFound])

            let status = keychainUpsert(add: { add.next() }, update: { update.next() })

            #expect(status == errSecItemNotFound)
            #expect(add.calls == 2)
            #expect(update.calls == 2)
        }

        @Test("Any other failure is returned as it happened, without a retry")
        func otherFailuresAreNotRetried() {
            var add = Script(statuses: [errSecInteractionNotAllowed])
            var update = Script(statuses: [])
            #expect(keychainUpsert(add: { add.next() }, update: { update.next() }) == errSecInteractionNotAllowed)
            #expect(add.calls == 1)
            #expect(update.calls == 0)

            var secondAdd = Script(statuses: [errSecDuplicateItem])
            var secondUpdate = Script(statuses: [errSecAuthFailed])
            #expect(
                keychainUpsert(add: { secondAdd.next() }, update: { secondUpdate.next() }) == errSecAuthFailed
            )
            #expect(secondAdd.calls == 1)
            #expect(secondUpdate.calls == 1)
        }
    }

    #if os(macOS)

        /// The opt-in is only meaningful on macOS, the one platform with two keychains.
        ///
        /// What can be asserted depends on how the test process is signed, and both outcomes
        /// are correct: an entitled process reaches the data protection keychain, and an
        /// unentitled one (`swift test`, which is how CI runs this) must be refused with
        /// `errSecMissingEntitlement`. The outcome that would be a bug is the third one — a
        /// silent fallback to the file-based keychain, where the write "succeeds" into the
        /// store whose namespace isolation the caller asked to avoid.
        @Suite("Keychain data protection opt-in")
        struct KeychainDataProtectionTests {

            private func service(_ label: String) -> String {
                "dev.securestore.tests.\(label).\(UUID().uuidString)"
            }

            @Test("The flag is off unless asked for")
            func defaultsToTheFileBasedKeychain() {
                #expect(KeychainSecureStore(service: "s").usesDataProtectionKeychain == false)
                #expect(KeychainSecureStore(SecureStoreConfiguration(service: "s")).usesDataProtectionKeychain == false)
                #expect(KeychainSecureStore(service: "s", usesDataProtectionKeychain: true).usesDataProtectionKeychain)
            }

            @Test("Opting in never falls back to the file-based keychain")
            func optInIsHonoredOrRefused() throws {
                let name = service("data-protection")
                let protected = KeychainSecureStore(service: name, usesDataProtectionKeychain: true)
                let fileBased = KeychainSecureStore(service: name)
                let value = Data("token".utf8)

                do {
                    try protected.set(value, for: "k")
                } catch SecureStoreError.platform(let failure) {
                    // Unentitled: refused loudly, and nothing was written anywhere.
                    #expect(failure.code == errSecMissingEntitlement)
                    #expect(failure.backend == .keychain)
                    #expect(try fileBased.data(for: "k") == nil)
                    return
                }

                // Entitled: the item is in the data protection keychain and only there.
                #expect(try protected.data(for: "k") == value)
                #expect(try fileBased.data(for: "k") == nil)
                try protected.removeAll()
            }
        }

    #endif

#endif

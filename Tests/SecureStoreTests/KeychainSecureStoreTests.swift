//
//  KeychainSecureStoreTests.swift
//  SecureStoreTests
//
//  Keychain-specific mechanics only. Behaviour every backend shares belongs in the contract
//  suite; this file covers what is purely a property of Keychain Services — that a write is two
//  calls and what happens when another process gets in between them, macOS's two keychains,
//  and the accessibility class.
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

    /// Every class, paired with the Security Services constant it must be written as. Spelled
    /// out rather than derived, so a case mapped to the wrong constant fails here.
    let accessibilityClasses: [(KeychainAccessibility, String)] = [
        (.afterFirstUnlock, kSecAttrAccessibleAfterFirstUnlock as String),
        (.afterFirstUnlockThisDeviceOnly, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String),
        (.whenUnlocked, kSecAttrAccessibleWhenUnlocked as String),
        (.whenUnlockedThisDeviceOnly, kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String),
    ]

    /// The class reaches both halves of a write.
    ///
    /// Asserted on the attributes `set` hands to Security rather than on a stored item, because
    /// the one keychain an unentitled `swift test` can write to — the macOS file-based one —
    /// records no class. The suite below reads the class back wherever it can be observed.
    @Suite("Keychain accessibility")
    struct KeychainAccessibilityTests {

        @Test("Existing callers keep kSecAttrAccessibleAfterFirstUnlock")
        func defaultsToAfterFirstUnlock() {
            let byService = KeychainSecureStore(service: "s")
            let byConfiguration = KeychainSecureStore(SecureStoreConfiguration(service: "s"))
            let withFlag = KeychainSecureStore(service: "s", usesDataProtectionKeychain: true)

            for store in [byService, byConfiguration, withFlag] {
                #expect(store.accessibility == .afterFirstUnlock)
                let written = store.addAttributes(for: "k", data: Data())[kSecAttrAccessible as String]
                #expect(written as? String == kSecAttrAccessibleAfterFirstUnlock as String)
            }
        }

        @Test(
            "The class is written when an item is added and when it is overwritten",
            arguments: accessibilityClasses
        )
        func classRidesOnAddAndUpdate(accessibility: KeychainAccessibility, constant: String) {
            let store = KeychainSecureStore(service: "s", accessibility: accessibility)
            let value = Data("token".utf8)

            #expect(store.accessibility == accessibility)
            #expect(accessibility.attributeValue as String == constant)

            let added = store.addAttributes(for: "k", data: value)
            #expect(added[kSecAttrAccessible as String] as? String == constant)
            #expect(added[kSecValueData as String] as? Data == value)

            let updated = store.updateAttributes(data: value)
            #expect(updated[kSecAttrAccessible as String] as? String == constant)
            #expect(updated[kSecValueData as String] as? Data == value)
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
                    // Unentitled: the write is refused loudly, and nothing was written anywhere.
                    #expect(failure.code == errSecMissingEntitlement)
                    #expect(failure.backend == .keychain)
                    #expect(try fileBased.data(for: "k") == nil)
                    // Reads are the limit of "loudly": Security reports the data protection
                    // keychain as *empty* to an unentitled process rather than refusing the
                    // query, so a read answers "absent" — never a value from the file-based
                    // keychain. Pinned so the documentation cannot overstate it.
                    try fileBased.set(value, for: "k")
                    defer { cleanUp(fileBased) }
                    #expect(try protected.data(for: "k") == nil)
                    #expect(try protected.keys(withPrefix: "") == [])
                    return
                }

                // Entitled: the item is in the data protection keychain and only there. (An
                // unentitled process cannot clean that keychain up either, which is why the
                // cleanup is scoped to this path.)
                defer { cleanUp(protected) }
                #expect(try protected.data(for: "k") == value)
                #expect(try fileBased.data(for: "k") == nil)
            }
        }

        /// The class as Security Services stored it, read back from a real keychain.
        ///
        /// Which assertions apply depends on how the test process is signed, as for the
        /// data protection opt-in above: `swift test` is unentitled, so in CI the data
        /// protection keychain refuses the write and only the file-based keychain is observable.
        @Suite("Keychain accessibility on macOS")
        struct KeychainAccessibilityReadBackTests {

            private func service(_ label: String) -> String {
                "dev.securestore.tests.\(label).\(UUID().uuidString)"
            }

            /// The item's attributes, read with `kSecReturnAttributes`; `nil` when it is absent.
            private func storedAttributes(
                service: String,
                key: String,
                usesDataProtectionKeychain: Bool
            ) throws -> [String: Any]? {
                var query: [String: Any] = [
                    kSecClass as String: kSecClassGenericPassword,
                    kSecAttrService as String: service,
                    kSecAttrAccount as String: key,
                    kSecReturnAttributes as String: true,
                    kSecMatchLimit as String: kSecMatchLimitOne,
                ]
                if usesDataProtectionKeychain {
                    query[kSecUseDataProtectionKeychain as String] = true
                }
                var result: CFTypeRef?
                let status = SecItemCopyMatching(query as CFDictionary, &result)
                if status == errSecItemNotFound { return nil }
                try #require(status == errSecSuccess, "SecItemCopyMatching failed with \(status)")
                return try #require(result as? [String: Any])
            }

            /// A class other than `accessibility`, so an overwrite has something to change.
            private func otherClass(than accessibility: KeychainAccessibility) -> KeychainAccessibility {
                accessibility == .whenUnlocked ? .afterFirstUnlock : .whenUnlocked
            }

            /// The file-based keychain is what `swift test` writes to and what every macOS caller
            /// gets by default, so the class must not break a write there — on the add or on the
            /// update — even though it is not kept. That it is *not* kept is pinned too, so the
            /// documentation cannot come to overstate what a `ThisDeviceOnly` class does on a Mac.
            @Test(
                "The file-based keychain accepts every class and records none",
                arguments: accessibilityClasses
            )
            func fileBasedKeychainRecordsNoClass(accessibility: KeychainAccessibility, constant: String) throws {
                let name = service("accessibility-file")
                let store = KeychainSecureStore(service: name, accessibility: accessibility)
                defer { cleanUp(store) }

                try store.set(Data("first".utf8), for: "k")
                try store.set(Data("second".utf8), for: "k")

                #expect(try store.data(for: "k") == Data("second".utf8))
                let attributes = try #require(
                    try storedAttributes(service: name, key: "k", usesDataProtectionKeychain: false)
                )
                #expect(attributes[kSecAttrAccessible as String] == nil, "expected no class, not \(constant)")
            }

            @Test(
                "The data protection keychain records the class on add and on update",
                arguments: accessibilityClasses
            )
            func dataProtectionKeychainRecordsTheClass(accessibility: KeychainAccessibility, constant: String) throws {
                let name = service("accessibility-data-protection")
                let first = KeychainSecureStore(
                    service: name,
                    accessibility: otherClass(than: accessibility),
                    usesDataProtectionKeychain: true
                )
                let store = KeychainSecureStore(
                    service: name,
                    accessibility: accessibility,
                    usesDataProtectionKeychain: true
                )

                do {
                    try store.set(Data("added".utf8), for: "added")
                } catch SecureStoreError.platform(let failure) {
                    // Unentitled: the class cannot be observed, and the refusal is the outcome the
                    // data protection opt-in suite already pins.
                    #expect(failure.code == errSecMissingEntitlement)
                    return
                }
                defer { cleanUp(store) }

                // First written with a different class, then overwritten by the store under
                // test: the update must re-class the item, not just replace its value.
                try first.set(Data("first".utf8), for: "updated")
                try store.set(Data("second".utf8), for: "updated")

                for key in ["added", "updated"] {
                    let attributes = try #require(
                        try storedAttributes(service: name, key: key, usesDataProtectionKeychain: true)
                    )
                    #expect(attributes[kSecAttrAccessible as String] as? String == constant, "key: \(key)")
                }
            }
        }

    #endif

#endif

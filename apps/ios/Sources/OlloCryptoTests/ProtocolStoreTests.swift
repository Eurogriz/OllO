import XCTest
@testable import OlloCrypto

final class ProtocolStoreTests: XCTestCase {
    private let wrap = Data(repeating: 11, count: 32)

    func testDurableDirectorySurvivesRestart() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("ollo-proto-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        let first = ProtocolStore(store: IdentityStore(directory: dir), wrapKey: wrap, localUserId: "u1", localDeviceId: "d1")
        try first.storeLocalIdentity(record: Data([9, 8, 7]), registrationId: 42)
        try first.storePreKey(id: 3, record: Data([1, 1, 1]))
        try first.storeSignedPreKey(id: 1, record: Data([2, 2]))
        try first.sessions.saveSession(
            SessionDirectory.Address(userId: "u2", deviceId: "d9"),
            record: Data([4, 5, 6])
        )
        try first.messages.put(LocalMessage(
            clientId: "c1",
            threadId: "t1",
            senderId: "u2",
            sentAt: 1000,
            status: "sent",
            body: Data([65])
        ))
        let idx = ThreadIndex()
        idx.upsert(ChatThread(id: "t1", title: "bob", peerUserId: "u2"))
        try first.saveThreads(idx)

        let again = ProtocolStore(store: IdentityStore(directory: dir), wrapKey: wrap, localUserId: "u1", localDeviceId: "d1")
        XCTAssertEqual(try again.loadLocalIdentity(), Data([9, 8, 7]))
        XCTAssertEqual(try again.registrationId(), 42)
        XCTAssertEqual(try again.loadPreKey(id: 3), Data([1, 1, 1]))
        XCTAssertEqual(try again.loadSignedPreKey(id: 1), Data([2, 2]))
        XCTAssertEqual(
            try again.sessions.loadSession(SessionDirectory.Address(userId: "u2", deviceId: "d9")),
            Data([4, 5, 6])
        )
        XCTAssertEqual(try again.planFetch(targetUserId: "u2", targetDeviceId: "d9"), .useSession)
        XCTAssertEqual(try again.loadThreads().visible().first?.title, "bob")
        XCTAssertEqual(try again.messages.list(threadId: "t1").first?.clientId, "c1")
    }

    func testConsumePrekeyAndIdentityChangeStayFailClosed() throws {
        let proto = ProtocolStore(store: IdentityStore(), wrapKey: wrap, localUserId: "u1", localDeviceId: "d1")
        try proto.storePreKey(id: 7, record: Data([9]))
        try proto.removePreKey(id: 7)
        XCTAssertNil(try proto.loadPreKey(id: 7))
        let addr = SessionDirectory.Address(userId: "u2", deviceId: "d9")
        XCTAssertEqual(try proto.sessions.noteRemoteIdentity(addr, identityX25519: Data(repeating: 1, count: 32)), .new)
        XCTAssertEqual(try proto.sessions.noteRemoteIdentity(addr, identityX25519: Data(repeating: 2, count: 32)), .changed)
        XCTAssertEqual(try proto.sessions.noteRemoteIdentity(addr, identityX25519: Data(repeating: 1, count: 32)), .unchanged)
    }

    func testMessageTtlExpiresAndWipeDeletesFiles() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("ollo-hist-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        let proto = ProtocolStore(store: IdentityStore(directory: dir), wrapKey: wrap)
        try proto.messages.put(LocalMessage(clientId: "live", threadId: "t1", senderId: "u1", sentAt: 1, status: "sent", body: Data([1]), expiresAt: 9000))
        try proto.messages.put(LocalMessage(clientId: "dead", threadId: "t1", senderId: "u1", sentAt: 2, status: "sent", body: Data([2]), expiresAt: 1000))
        XCTAssertEqual(try proto.messages.expire(now: 2000), 1)
        XCTAssertEqual(try proto.messages.list(threadId: "t1").map(\.clientId), ["live"])
        proto.wipe()
        XCTAssertTrue(IdentityStore(directory: dir).isEmpty)
    }

    func testMessageCodecKnownAnswer() throws {
        let msg = LocalMessage(clientId: "c", threadId: "t", senderId: "s", sentAt: 1, status: "sent", body: Data([0xAA]))
        let encoded = try LocalMessageCodec.encode(msg)
        XCTAssertEqual(Array(encoded.prefix(7)), [0x4F, 0x4C, 0x4D, 0x32, 0x00, 0x01, 0x63])
        let back = try LocalMessageCodec.decode(encoded)
        XCTAssertEqual(back.clientId, "c")
        XCTAssertEqual(back.threadId, "t")
        XCTAssertNil(back.expiresAt)
        XCTAssertEqual(back.body, Data([0xAA]))
    }

    func testPruneSignedPreKeysKeepsCurrentAndTwoRetired() throws {
        let proto = ProtocolStore(store: IdentityStore(), wrapKey: wrap)
        try proto.storeSignedPreKey(id: 1, record: Data([1]))
        try proto.storeSignedPreKey(id: 2, record: Data([2]))
        try proto.storeSignedPreKey(id: 3, record: Data([3]))
        try proto.storeSignedPreKey(id: 4, record: Data([4]))
        try proto.storeSignedPreKey(id: 5, record: Data([5]))
        try proto.pruneSignedPreKeys(currentId: 5)
        XCTAssertNil(try proto.loadSignedPreKey(id: 1))
        XCTAssertNil(try proto.loadSignedPreKey(id: 2))
        XCTAssertEqual(try proto.loadSignedPreKey(id: 3), Data([3]))
        XCTAssertEqual(try proto.loadSignedPreKey(id: 4), Data([4]))
        XCTAssertEqual(try proto.loadSignedPreKey(id: 5), Data([5]))
    }

    func testAccountKeySurvivesRestartAndIsNotReminted() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("ollo-account-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        let first = ProtocolStore(store: IdentityStore(directory: dir), wrapKey: wrap)
        let a = try first.accountVault.getOrCreate()
        let again = ProtocolStore(store: IdentityStore(directory: dir), wrapKey: wrap)
        let b = try again.accountVault.getOrCreate()
        XCTAssertEqual(a.publicKey, b.publicKey)
        XCTAssertEqual(a.privateKey.rawRepresentation, b.privateKey.rawRepresentation)
        again.wipe()
        let third = ProtocolStore(store: IdentityStore(directory: dir), wrapKey: wrap)
        let c = try third.accountVault.getOrCreate()
        XCTAssertNotEqual(a.publicKey, c.publicKey)
    }

    func testIdentityExtrasAndPrekeyIdsRoundTrip() throws {
        let proto = ProtocolStore(store: IdentityStore(), wrapKey: wrap)
        try proto.storeLocalIdentity(record: Data([1, 2, 3]), registrationId: 7, extras: ["device_ed25519_seed": Data([9])])
        try proto.storePreKey(id: 4, record: Data([4]))
        try proto.storeSignedPreKey(id: 2, record: Data([2]))
        XCTAssertEqual(try proto.loadIdentityField("device_ed25519_seed"), Data([9]))
        XCTAssertEqual(try proto.preKeyIds(), [4])
        XCTAssertEqual(try proto.signedPreKeyIds(), [2])
    }

    func testRejectsPathTraversalKeys() {
        let store = IdentityStore()
        XCTAssertThrowsError(try store.put(wrapKey: wrap, key: "../etc", plaintext: Data([1])))
    }
}

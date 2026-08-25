import XCTest
@testable import OlloCrypto

final class SessionDirectoryTests: XCTestCase {
    private let wrap = Data(repeating: 9, count: 32)

    func testBlobMapKnownAnswer() throws {
        let encoded = try BlobMap.encode(["a": Data([0xFF])])
        let expected = Data([
            0x4F, 0x4C, 0x4D, 0x31,
            0x00, 0x00, 0x00, 0x01,
            0x00, 0x01, 0x61,
            0x00, 0x00, 0x00, 0x01, 0xFF,
        ])
        XCTAssertEqual(encoded, expected)
        let back = try BlobMap.decode(encoded)
        XCTAssertEqual(back["a"], Data([0xFF]))
    }

    func testPersistsOpaqueSessionAndPlansFetch() throws {
        let dir = SessionDirectory(
            store: IdentityStore(),
            wrapKey: wrap,
            localUserId: "u1",
            localDeviceId: "d1"
        )
        let peer = SessionDirectory.Address(userId: "u2", deviceId: "d9")
        XCTAssertEqual(try dir.planFetch(targetUserId: "u2", targetDeviceId: "d9"), .consumeBundle)
        try dir.saveSession(peer, record: Data([1, 2, 3, 4]))
        XCTAssertTrue(try dir.hasSession(peer))
        XCTAssertEqual(try dir.loadSession(peer), Data([1, 2, 3, 4]))
        XCTAssertEqual(try dir.planFetch(targetUserId: "u2", targetDeviceId: "d9"), .useSession)
        XCTAssertEqual(try dir.planFetch(targetUserId: "u1", targetDeviceId: "d1"), .skipSelf)
    }

    func testIdentityChangeDoesNotOverwrite() throws {
        let dir = SessionDirectory(store: IdentityStore(), wrapKey: wrap)
        let addr = SessionDirectory.Address(userId: "u2", deviceId: "d9")
        let first = Data(repeating: 1, count: 32)
        let second = Data(repeating: 2, count: 32)
        XCTAssertEqual(try dir.noteRemoteIdentity(addr, identityX25519: first), .new)
        XCTAssertEqual(try dir.noteRemoteIdentity(addr, identityX25519: first), .unchanged)
        XCTAssertEqual(try dir.noteRemoteIdentity(addr, identityX25519: second), .changed)
        XCTAssertEqual(try dir.noteRemoteIdentity(addr, identityX25519: first), .unchanged)
        try dir.replaceRemoteIdentity(addr, identityX25519: second)
        XCTAssertEqual(try dir.noteRemoteIdentity(addr, identityX25519: second), .unchanged)
    }

    func testWipeDropsSessionsAndIdentities() throws {
        let store = IdentityStore()
        let dir = SessionDirectory(store: store, wrapKey: wrap, localUserId: "u1", localDeviceId: "d1")
        try dir.saveSession(SessionDirectory.Address(userId: "u2", deviceId: "d9"), record: Data([7]))
        _ = try dir.noteRemoteIdentity(
            SessionDirectory.Address(userId: "u2", deviceId: "d9"),
            identityX25519: Data(repeating: 3, count: 32)
        )
        dir.wipe()
        XCTAssertTrue(store.isEmpty)
        let again = SessionDirectory(store: store, wrapKey: wrap, localUserId: "u1", localDeviceId: "d1")
        XCTAssertFalse(try again.hasSession(SessionDirectory.Address(userId: "u2", deviceId: "d9")))
        XCTAssertNil(try again.loadSession(SessionDirectory.Address(userId: "u2", deviceId: "d9")))
        XCTAssertEqual(try again.planFetch(targetUserId: "u2", targetDeviceId: "d9"), .consumeBundle)
    }

    func testUnboundEngineFailsClosed() {
        let engine = UnboundCryptoEngine()
        XCTAssertThrowsError(try engine.encrypt(sessionId: "x", plaintext: Data([1])))
        let digits = engine.safetyNumber(local: Data(repeating: 1, count: 32), remote: Data(repeating: 2, count: 32))
        XCTAssertEqual(digits.count, 60)
    }
}

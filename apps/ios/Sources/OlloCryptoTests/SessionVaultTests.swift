import XCTest
@testable import OlloCrypto

final class SessionVaultTests: XCTestCase {
    private let wrap = Data(repeating: 5, count: 32)

    func testSealsTokensAndWipesOnRefreshReject() throws {
        let store = IdentityStore()
        let proto = ProtocolStore(store: store, wrapKey: wrap)
        try proto.sessionVault.save(SessionSecrets(userId: "u1", deviceId: "d1", access: "access-secret", refresh: "refresh-secret"))
        XCTAssertEqual(try proto.sessionVault.load()?.refresh, "refresh-secret")
        XCTAssertEqual(EnvelopePlanner.onRefreshRejected(), .wipe)
        proto.wipe()
        XCTAssertNil(try SessionVault(store: store, wrapKey: wrap).load())
        XCTAssertTrue(store.isEmpty)
    }

    func testRosterHashChangesWhenACloneDeviceAppears() {
        let ik = Data(repeating: 1, count: 32)
        let one = DeviceRoster.hash([DeviceRoster.Device(deviceId: "d1", identityX25519: ik)])
        let two = DeviceRoster.hash([
            DeviceRoster.Device(deviceId: "d2", identityX25519: ik),
            DeviceRoster.Device(deviceId: "d1", identityX25519: ik),
        ])
        XCTAssertNotEqual(one, two)
        XCTAssertEqual(DeviceRoster.note(previous: one, next: two), .changed)
        XCTAssertEqual(DeviceRoster.note(previous: two, next: two), .unchanged)
    }

    func testReplenishOnlyWhenDepthIsLow() {
        XCTAssertNil(EnvelopePlanner.planPrekeyReplenish(remaining: 20, nextId: 11))
        let plan = EnvelopePlanner.planPrekeyReplenish(remaining: 19, nextId: 11)
        XCTAssertEqual(plan?.count, 100)
        XCTAssertEqual(plan?.startId, 11)
    }

    func testDropsAReplayedEnvelopeAndClearsOnWipe() throws {
        let store = IdentityStore()
        let proto = ProtocolStore(store: store, wrapKey: wrap)
        XCTAssertEqual(try proto.rememberEnvelope("e1"), .accept)
        XCTAssertEqual(try proto.rememberEnvelope("e1"), .drop)
        XCTAssertEqual(try proto.rememberEnvelope("e2"), .accept)
        var ids = ["a", "b"]
        XCTAssertEqual(EnvelopePlanner.rememberEnvelope(&ids, envelopeId: "c", max: 2), .accept)
        XCTAssertEqual(ids, ["b", "c"])
        proto.wipe()
        XCTAssertEqual(try ProtocolStore(store: store, wrapKey: wrap).rememberEnvelope("e1"), .accept)
    }

    func testControllerRotatesTokensAndWipesOnFailedRefresh() throws {
        let store = IdentityStore()
        let proto = ProtocolStore(store: store, wrapKey: wrap, localUserId: "u1", localDeviceId: "d1")
        try proto.sessions.saveSession(
            SessionDirectory.Address(userId: "u2", deviceId: "d9"),
            record: Data([1, 2, 3])
        )
        let ctl = SessionController(proto: proto)
        try ctl.save(SessionSecrets(userId: "u1", deviceId: "d1", access: "access-1", refresh: "refresh-1"))
        XCTAssertEqual(try ctl.restore()?.access, "access-1")
        XCTAssertTrue(try ctl.applyRefresh(access: "access-2", refresh: "refresh-2"))
        XCTAssertEqual(try proto.sessionVault.load()?.refresh, "refresh-2")
        XCTAssertEqual(ctl.onUnauthorized(refreshSucceeded: true), .retry)
        XCTAssertEqual(ctl.access(), "access-2")
        XCTAssertEqual(ctl.onUnauthorized(refreshSucceeded: false), .wipe)
        XCTAssertNil(ctl.access())
        XCTAssertNil(try proto.sessionVault.load())
        XCTAssertNil(try proto.sessions.loadSession(SessionDirectory.Address(userId: "u2", deviceId: "d9")))
        XCTAssertTrue(store.isEmpty)
    }
}

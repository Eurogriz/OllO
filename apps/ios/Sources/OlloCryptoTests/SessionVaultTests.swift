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
}

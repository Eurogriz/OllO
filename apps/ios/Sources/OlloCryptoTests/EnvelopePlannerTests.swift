import XCTest
@testable import OlloCrypto

final class EnvelopePlannerTests: XCTestCase {
    func testRetriesThenFailsClosed() {
        var item = EnvelopePlanner.OutboxItem(id: "m1", status: .pending, attempts: 0)
        for _ in 0..<(EnvelopePlanner.maxAttempts - 1) {
            item = EnvelopePlanner.onSendFailure(item)
            XCTAssertEqual(item.status, .retrying)
        }
        item = EnvelopePlanner.onSendFailure(item)
        XCTAssertEqual(item.status, .failed)
        XCTAssertEqual(item.attempts, EnvelopePlanner.maxAttempts)
        XCTAssertEqual(EnvelopePlanner.nextRetryDelayMs(attempts: 0), 1500)
        XCTAssertEqual(EnvelopePlanner.nextRetryDelayMs(attempts: 3), 12000)
    }

    func testSkipsSelfAndDoesNotBurnOpkWhenSessionExists() {
        XCTAssertEqual(
            EnvelopePlanner.planKeyFetch(
                localUserId: "u1",
                localDeviceId: "d1",
                targetUserId: "u1",
                targetDeviceId: "d1",
                hasSession: false
            ),
            .skipSelf
        )
        XCTAssertEqual(
            EnvelopePlanner.planKeyFetch(
                localUserId: "u1",
                localDeviceId: "d1",
                targetUserId: "u2",
                targetDeviceId: "d9",
                hasSession: true
            ),
            .useSession
        )
        XCTAssertEqual(
            EnvelopePlanner.planKeyFetch(
                localUserId: "u1",
                localDeviceId: "d1",
                targetUserId: "u2",
                targetDeviceId: "d9",
                hasSession: false
            ),
            .consumeBundle
        )
    }

    func testRotatesSignedPrekeyOnlyAfterMaxAge() {
        let now: Int64 = 1_700_000_000_000
        XCTAssertNil(EnvelopePlanner.planSignedPrekeyRotation(currentId: 1, createdAtMs: now, now: now))
        XCTAssertNil(EnvelopePlanner.planSignedPrekeyRotation(currentId: 1, createdAtMs: nil, now: now))
        XCTAssertNil(EnvelopePlanner.planSignedPrekeyRotation(currentId: 0, createdAtMs: 1, now: now))
        XCTAssertEqual(
            EnvelopePlanner.planSignedPrekeyRotation(
                currentId: 1,
                createdAtMs: now - EnvelopePlanner.signedPrekeyMaxAgeMs,
                now: now
            )?.nextId,
            2
        )
        XCTAssertEqual(EnvelopePlanner.keepSignedPrekeyIds(currentId: 5, storedIds: [1, 2, 3, 4, 5]), [5, 4, 3])
        XCTAssertEqual(EnvelopePlanner.afterUnauthorized(refreshSucceeded: true), .retry)
        XCTAssertEqual(EnvelopePlanner.afterUnauthorized(refreshSucceeded: false), .wipe)
        XCTAssertEqual(
            EnvelopePlanner.planRosterPrune(sessionKeys: ["u1:d1", "u1:d2", "u10:d1"], userId: "u1", liveDeviceIds: ["d1"]),
            ["u1:d2"]
        )
        XCTAssertEqual(
            EnvelopePlanner.planDeviceDrop(sessionKeys: ["u1:d1", "u1:d2"], userId: "u1", deviceId: "d2"),
            ["u1:d2"]
        )
        XCTAssertEqual(EnvelopePlanner.planSessionAccept(userId: "u1", deviceId: "d2", droppedDevices: ["u1:d2"]), "drop")
        XCTAssertEqual(EnvelopePlanner.planSessionAccept(userId: "u1", deviceId: "d1", droppedDevices: ["u1:d2"]), "accept")
        XCTAssertEqual(EnvelopePlanner.planSessionAccept(userId: "u1", deviceId: "", droppedDevices: []), "drop")
        XCTAssertEqual(
            EnvelopePlanner.planDeviceDropNotice(
                senderUserId: "u1",
                senderDeviceId: "phone",
                targetUserId: "u1",
                targetDeviceId: "stolen",
                liveDeviceIds: ["phone"]
            ),
            "apply"
        )
        XCTAssertEqual(
            EnvelopePlanner.planDeviceDropNotice(
                senderUserId: "u1",
                senderDeviceId: "stolen",
                targetUserId: "u1",
                targetDeviceId: "phone",
                liveDeviceIds: ["phone", "stolen"]
            ),
            "drop"
        )
        XCTAssertEqual(
            EnvelopePlanner.planDeviceDropNotice(
                senderUserId: "eve",
                senderDeviceId: "d9",
                targetUserId: "u1",
                targetDeviceId: "phone",
                liveDeviceIds: ["phone"]
            ),
            "drop"
        )
        XCTAssertEqual(
            EnvelopePlanner.planDeviceDropNotice(
                senderUserId: "u1",
                senderDeviceId: "phone",
                targetUserId: "u1",
                targetDeviceId: "stolen",
                liveDeviceIds: nil
            ),
            "drop"
        )
    }

    func testLaunchSkipsOtpWhenVaultHasSession() {
        XCTAssertEqual(EnvelopePlanner.planSessionLaunch(hasVaultSession: true), .signedIn)
        XCTAssertEqual(EnvelopePlanner.planSessionLaunch(hasVaultSession: false), .needAuth)
    }

    func testUnboundEngineDoesNotInventIdentity() {
        XCTAssertThrowsError(try UnboundCryptoEngine().generateIdentity()) { error in
            XCTAssertEqual(error as? UnboundCryptoEngine.EngineError, .unbound)
        }
    }

    func testUnboundEngineDoesNotInventRegistration() {
        XCTAssertThrowsError(try UnboundCryptoEngine().deviceRegistrationJson(name: "iPhone", platform: "ios")) { error in
            XCTAssertEqual(error as? UnboundCryptoEngine.EngineError, .unbound)
        }
    }
}

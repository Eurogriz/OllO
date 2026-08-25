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
    }

    func testUnboundEngineDoesNotInventIdentity() {
        XCTAssertThrowsError(try UnboundCryptoEngine().generateIdentity()) { error in
            XCTAssertEqual(error as? UnboundCryptoEngine.EngineError, .unbound)
        }
    }
}

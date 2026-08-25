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
}

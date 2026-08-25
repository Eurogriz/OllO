import XCTest
@testable import OlloCrypto

final class ThreadIndexTests: XCTestCase {
    func testStartsEmptyAndNeverSeedsDemoChats() {
        let index = ThreadIndex()
        XCTAssertTrue(index.isEmpty)
        XCTAssertTrue(index.visible().isEmpty)
        index.upsert(ChatThread(id: "t1", title: "bob", peerUserId: "u-bob"))
        XCTAssertEqual(index.visible().count, 1)
        index.archive("t1")
        XCTAssertTrue(index.isEmpty)
        index.wipe()
        XCTAssertTrue(index.visible().isEmpty)
    }
}

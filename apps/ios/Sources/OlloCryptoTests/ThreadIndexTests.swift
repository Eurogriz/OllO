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

    func testRoundTripsIncludingArchived() throws {
        let index = ThreadIndex()
        index.upsert(ChatThread(id: "t1", title: "bob", preview: "hi", peerUserId: "u-bob", muted: true))
        index.upsert(ChatThread(id: "t2", title: "team", groupId: "g1", archived: true))
        let back = try ThreadIndex.decode(try index.encode())
        XCTAssertEqual(back.visible().first?.title, "bob")
        XCTAssertEqual(back.visible().first?.muted, true)
        XCTAssertEqual(back.snapshot().count, 2)
        XCTAssertEqual(back.snapshot().first(where: { $0.id == "t2" })?.groupId, "g1")
    }
}

import XCTest
@testable import OlloCrypto

final class AesGcmWrapTests: XCTestCase {
    func testRoundTripAndTamperFails() throws {
        let key = Data(repeating: 7, count: 32)
        let pt = Data("x25519-private-must-not-be-plaintext".utf8)
        let blob = try AesGcmWrap.seal(key: key, plaintext: pt)
        XCTAssertEqual(try AesGcmWrap.open(key: key, blob: blob), pt)
        XCTAssertThrowsError(try AesGcmWrap.open(key: Data(repeating: 8, count: 32), blob: blob))
        var bad = blob
        bad[bad.count - 1] ^= 1
        XCTAssertThrowsError(try AesGcmWrap.open(key: key, blob: bad))
    }
}

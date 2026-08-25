import XCTest
@testable import OlloCrypto

final class SafetyNumberTests: XCTestCase {
    func testKnownAnswerVector() {
        let a = Data(repeating: 1, count: 32)
        let b = Data(repeating: 2, count: 32)
        let s = SafetyNumber.of(identityA: a, identityB: b)
        XCTAssertEqual(s.digits, "153665515321528787008757103930069366995789004059450082545955")
        XCTAssertEqual(s.hex, "f1d7e960a6cd69014103fcdd5ff23a894e93c8008057e107ab6e6795df5a9003")
        XCTAssertEqual(s.digits, SafetyNumber.of(identityA: b, identityB: a).digits)
        XCTAssertEqual(s.digits.count, 60)
    }
}

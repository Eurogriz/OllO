import XCTest
@testable import OlloCrypto

final class IdentityAddressTests: XCTestCase {
    func testEncodeParseAndAuthProof() {
        let ik = Data(repeating: 7, count: 32)
        let uri = IdentityAddress.encode(ik)
        XCTAssertTrue(uri.hasPrefix(IdentityAddress.prefix))
        XCTAssertEqual(IdentityAddress.parse(uri), ik)
        XCTAssertEqual(IdentityAddress.parse(String(uri.dropFirst(IdentityAddress.prefix.count))), ik)
        XCTAssertNil(IdentityAddress.parse(""))
        XCTAssertNil(IdentityAddress.parse("ollo:user:v1:???"))
        XCTAssertEqual(IdentityAddress.encode(Data(repeating: 0, count: 32)), "")
        let proof = IdentityAddress.authProof(challengeId: "ch_1", nonce: "nonce-a")
        let domain = Data(IdentityAddress.authProofDomain.utf8)
        XCTAssertEqual(proof.prefix(domain.count), domain)
        XCTAssertEqual(IdentityAddress.authProof(challengeId: "", nonce: "n").count, 0)
    }

    func testPrefixDjbRejectsWrongLength() throws {
        XCTAssertThrowsError(try LibsignalEngine.prefixDjb(Data()))
        XCTAssertThrowsError(try LibsignalEngine.prefixDjb(Data(repeating: 1, count: 31)))
        XCTAssertThrowsError(try LibsignalEngine.prefixDjb(Data(repeating: 1, count: 33)))
        let ok = try LibsignalEngine.prefixDjb(Data(repeating: 1, count: 32))
        XCTAssertEqual(ok.count, 33)
        XCTAssertEqual(ok.first, LibsignalEngine.djbType)
        XCTAssertEqual(try LibsignalEngine.stripDjb(ok), Data(repeating: 1, count: 32))
        XCTAssertThrowsError(try LibsignalEngine.stripDjb(Data(repeating: 1, count: 32)))
    }
}

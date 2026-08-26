import XCTest
@testable import OlloCrypto
@testable import OlloNetwork

final class AuthRepositoryTests: XCTestCase {
    override func tearDown() {
        MockURLProtocol.reset()
        super.tearDown()
    }

    func testParseOtpAndSessionFailClosed() throws {
        let otp = try AuthPayload.parseOtpChallenge(Data(#"{"challenge_id":"ch1","dev_otp":"123456"}"#.utf8))
        XCTAssertEqual(otp.challengeId, "ch1")
        XCTAssertEqual(otp.devOtp, "123456")
        XCTAssertThrowsError(try AuthPayload.parseOtpChallenge(Data(#"{"expires_in":300}"#.utf8)))
        XCTAssertThrowsError(try AuthPayload.parseSession(Data(#"{"device_id":"d1"}"#.utf8)))
        XCTAssertThrowsError(try AuthPayload.parseRefresh(Data(#"{"access_token":"a"}"#.utf8)))
        let session = try AuthPayload.parseSession(Data(#"""
        {"user":{"id":"u1","username":null},"device_id":"d1","access_token":"acc","refresh_token":"ref"}
        """#.utf8))
        XCTAssertEqual(session.userId, "u1")
        XCTAssertNil(session.username)
        XCTAssertEqual(session.refresh, "ref")
    }

    func testVerifyBodyDoesNotInventRegistrationIds() throws {
        XCTAssertThrowsError(
            try AuthPayload.verifyBody(challengeId: "ch", otp: "123456", deviceJson: #"{"name":"iPhone"}"#)
        ) { error in
            XCTAssertEqual(error as? AuthPayload.Error, .missingDevice)
        }
        XCTAssertThrowsError(
            try AuthPayload.verifyBody(challengeId: "ch", otp: "123456", deviceJson: "not-json")
        )
        let fixture = boundEngineFixture()
        let body = try AuthPayload.verifyBody(challengeId: "ch", otp: "123456", deviceJson: fixture)
        let obj = try JSONSerialization.jsonObject(with: body) as? [String: Any]
        let device = obj?["device"] as? [String: Any]
        XCTAssertEqual(device?["registration_id"] as? Int, 4242)
        XCTAssertEqual(obj?["challenge_id"] as? String, "ch")
        XCTAssertNil(obj?["registration_id"])
    }

    func testUnboundSignInDoesNotRequestOtp() async {
        var hit = false
        MockURLProtocol.handler = { _ in
            hit = true
            return (500, Data())
        }
        let repo = AuthRepository.connected(
            baseURL: URL(string: "https://api.ollo.example")!,
            sessions: SessionController(proto: ProtocolStore(store: IdentityStore(), wrapKey: Data(repeating: 5, count: 32))),
            urlSession: MockURLProtocol.session()
        )
        do {
            _ = try await repo.signIn(
                engine: UnboundCryptoEngine(),
                phone: "+70000000000",
                otp: "123456",
                name: "iPhone",
                platform: "ios"
            )
            XCTFail("expected unbound engine to fail closed")
        } catch let error as UnboundCryptoEngine.EngineError {
            XCTAssertEqual(error, .unbound)
        } catch {
            XCTFail("unexpected \(error)")
        }
        XCTAssertFalse(hit)
    }

    func testVerifyPersistsVaultTokens() async throws {
        MockURLProtocol.handler = { req in
            XCTAssertEqual(req.url?.path, "/v1/auth/verify-otp")
            return (200, Data(#"""
            {"user":{"id":"u1","username":"ada"},"device_id":"d1","access_token":"acc-1","refresh_token":"ref-1"}
            """#.utf8))
        }
        let proto = ProtocolStore(store: IdentityStore(), wrapKey: Data(repeating: 5, count: 32))
        let sessions = SessionController(proto: proto)
        let repo = AuthRepository.connected(
            baseURL: URL(string: "https://api.ollo.example")!,
            sessions: sessions,
            urlSession: MockURLProtocol.session()
        )
        let session = try await repo.verify(
            challengeId: "ch",
            otp: "123456",
            deviceJson: boundEngineFixture()
        )
        XCTAssertEqual(session.deviceId, "d1")
        XCTAssertEqual(try sessions.restore()?.access, "acc-1")
        XCTAssertEqual(try sessions.launch(), .signedIn)
    }

    func testUnauthorizedRefreshThenWipe() async throws {
        let proto = ProtocolStore(store: IdentityStore(), wrapKey: Data(repeating: 5, count: 32))
        let sessions = SessionController(proto: proto)
        try sessions.save(SessionSecrets(userId: "u1", deviceId: "d1", access: "old-acc", refresh: "old-ref"))
        let repo = AuthRepository.connected(
            baseURL: URL(string: "https://api.ollo.example")!,
            sessions: sessions,
            urlSession: MockURLProtocol.session()
        )
        MockURLProtocol.handler = { req in
            let path = req.url?.path ?? ""
            if path == "/v1/users/search" {
                if req.value(forHTTPHeaderField: "Authorization") == "Bearer acc-2" {
                    return (200, Data(#"{"id":"u2"}"#.utf8))
                }
                return (401, Data())
            }
            if path == "/v1/auth/refresh" {
                return (200, Data(#"{"access_token":"acc-2","refresh_token":"ref-2"}"#.utf8))
            }
            return (500, Data())
        }
        let ok = try await repo.client.searchUsername("ada")
        XCTAssertEqual(String(data: ok, encoding: .utf8), #"{"id":"u2"}"#)
        XCTAssertEqual(try sessions.restore()?.refresh, "ref-2")

        MockURLProtocol.handler = { req in
            let path = req.url?.path ?? ""
            if path == "/v1/users/search" { return (401, Data()) }
            if path == "/v1/auth/refresh" { return (401, Data()) }
            return (500, Data())
        }
        do {
            _ = try await repo.client.searchUsername("ada")
            XCTFail("expected wipe after rejected refresh")
        } catch {
            XCTAssertEqual((error as? URLError)?.code, .userAuthenticationRequired)
        }
        XCTAssertNil(try sessions.restore())
        XCTAssertTrue(proto.store.isEmpty)
    }

    /// Server-shaped fixture as a bound libsignal engine would emit. Not client-invented.
    private func boundEngineFixture() -> String {
        """
        {"name":"iPhone","platform":"ios","identity_key_x25519":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","identity_key_ed25519":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","registration_id":4242,"signed_prekey":{"id":7,"public":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","signature":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="},"one_time_prekeys":[{"id":11,"public":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}]}
        """
    }
}

final class MockURLProtocol: URLProtocol {
    static var handler: ((URLRequest) -> (Int, Data))?
    private static let lock = NSLock()

    static func reset() {
        lock.lock()
        handler = nil
        lock.unlock()
    }

    static func session() -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [MockURLProtocol.self]
        return URLSession(configuration: config)
    }

    override class func canInit(with request: URLRequest) -> Bool { true }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        Self.lock.lock()
        let handler = Self.handler
        Self.lock.unlock()
        let (code, body) = handler?(request) ?? (500, Data())
        let res = HTTPURLResponse(
            url: request.url ?? URL(string: "https://api.ollo.example/")!,
            statusCode: code,
            httpVersion: nil,
            headerFields: ["Content-Type": "application/json"]
        )!
        client?.urlProtocol(self, didReceive: res, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: body)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

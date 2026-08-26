import Foundation

public actor OlloClient {
    public var baseURL: URL
    public var token: @Sendable () -> String?
    public var refreshTokens: (@Sendable () async -> Bool)?
    public var onWipe: (@Sendable () -> Void)?
    private let session: URLSession

    public init(
        baseURL: URL,
        session: URLSession = .shared,
        token: @escaping @Sendable () -> String? = { nil },
        refreshTokens: (@Sendable () async -> Bool)? = nil,
        onWipe: (@Sendable () -> Void)? = nil
    ) {
        self.baseURL = baseURL
        self.session = session
        self.token = token
        self.refreshTokens = refreshTokens
        self.onWipe = onWipe
    }

    public func requestOTP(phone: String) async throws -> Data {
        try await post(path: "/v1/auth/request-otp", body: ["phone_e164": phone], auth: false)
    }

    public func authChallenge() async throws -> Data {
        try await post(path: "/v1/auth/challenge", data: Data("{}".utf8), auth: false)
    }

    public func registerKey(body: Data) async throws -> Data {
        try await post(path: "/v1/auth/register-key", data: body, auth: false)
    }

    public func verifyOTP(body: Data) async throws -> Data {
        try await post(path: "/v1/auth/verify-otp", data: body, auth: false)
    }

    public func searchAddress(_ address: String) async throws -> Data {
        try await post(path: "/v1/users/search", body: ["address": address], auth: true)
    }

    /// Unauthenticated. A 401 here must not recurse into another refresh.
    public func refreshSession(_ refreshToken: String) async throws -> Data {
        try await post(
            path: "/v1/auth/refresh",
            body: ["refresh_token": refreshToken],
            auth: false,
            allowRefresh: false
        )
    }

    public func sendEnvelopes(json: Data) async throws -> Data {
        try await post(path: "/v1/envelopes", data: json, auth: true)
    }

    public func listDevices(of userId: String) async throws -> Data {
        try await get(path: "/v1/keys/\(userId)/devices", auth: true)
    }

    public func consumeBundle(userId: String, deviceId: String) async throws -> Data {
        try await get(path: "/v1/keys/\(userId)/\(deviceId)", auth: true)
    }

    public func peekBundle(userId: String, deviceId: String) async throws -> Data {
        try await get(path: "/v1/keys/\(userId)/\(deviceId)?consume=0", auth: true)
    }

    public func searchUsername(_ username: String) async throws -> Data {
        try await post(path: "/v1/users/search", body: ["username": username], auth: true)
    }

    public func presence(of userId: String) async throws -> Data {
        try await get(path: "/v1/presence/\(userId)", auth: true)
    }

    public func mailbox() async throws -> Data {
        try await get(path: "/v1/envelopes?limit=100", auth: true)
    }

    public func ack(ids: [String]) async throws -> Data {
        let data = try JSONSerialization.data(withJSONObject: ["ids": ids])
        return try await post(path: "/v1/envelopes/ack", data: data, auth: true)
    }

    /// Ciphertext bytes. Grant travels in `X-Attachment-Grant`, never in the URL.
    public func downloadAttachment(objectId: String, grant: String?) async throws -> Data {
        var req = URLRequest(url: url("/v1/attachments/\(objectId)/data"))
        req.httpMethod = "GET"
        if let access = token() {
            req.setValue("Bearer \(access)", forHTTPHeaderField: "Authorization")
        }
        if let grant, !grant.isEmpty {
            req.setValue(grant, forHTTPHeaderField: "X-Attachment-Grant")
        }
        return try await send(req, allowRefresh: true)
    }

    private func get(path: String, auth: Bool) async throws -> Data {
        var req = URLRequest(url: url(path))
        req.httpMethod = "GET"
        if auth, let access = token() {
            req.setValue("Bearer \(access)", forHTTPHeaderField: "Authorization")
        }
        return try await send(req, allowRefresh: true)
    }

    private func post(path: String, body: [String: String], auth: Bool, allowRefresh: Bool = true) async throws -> Data {
        let data = try JSONSerialization.data(withJSONObject: body)
        return try await post(path: path, data: data, auth: auth, allowRefresh: allowRefresh)
    }

    private func post(path: String, data: Data, auth: Bool, allowRefresh: Bool = true) async throws -> Data {
        var req = URLRequest(url: url(path))
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if auth, let access = token() {
            req.setValue("Bearer \(access)", forHTTPHeaderField: "Authorization")
        }
        req.httpBody = data
        return try await send(req, allowRefresh: allowRefresh)
    }

    private func send(_ req: URLRequest, allowRefresh: Bool) async throws -> Data {
        let (out, res) = try await session.data(for: req)
        guard let http = res as? HTTPURLResponse else { throw URLError(.badServerResponse) }
        if http.statusCode == 401 {
            guard allowRefresh else {
                wipe()
                throw URLError(.userAuthenticationRequired)
            }
            let ok = await refreshTokens?() ?? false
            guard ok else {
                wipe()
                throw URLError(.userAuthenticationRequired)
            }
            var retry = req
            if let access = token() {
                retry.setValue("Bearer \(access)", forHTTPHeaderField: "Authorization")
            }
            let (out2, res2) = try await session.data(for: retry)
            guard let http2 = res2 as? HTTPURLResponse, (200..<300).contains(http2.statusCode) else {
                wipe()
                throw URLError(.userAuthenticationRequired)
            }
            return out2
        }
        guard (200..<300).contains(http.statusCode) else { throw URLError(.badServerResponse) }
        return out
    }

    private func wipe() {
        onWipe?()
    }

    private func url(_ path: String) -> URL {
        URL(string: path, relativeTo: baseURL)!.absoluteURL
    }
}

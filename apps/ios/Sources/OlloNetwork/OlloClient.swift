import Foundation

public actor OlloClient {
    public var baseURL: URL
    public var accessToken: String?
    public var refreshToken: String?

    public init(baseURL: URL) {
        self.baseURL = baseURL
    }

    public func requestOTP(phone: String) async throws -> Data {
        try await post(path: "/v1/auth/request-otp", body: ["phone_e164": phone], auth: false)
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

    public func searchUsername(_ username: String) async throws -> Data {
        try await post(path: "/v1/users/search", body: ["username": username], auth: true)
    }

    public func presence(of userId: String) async throws -> Data {
        try await get(path: "/v1/presence/\(userId)", auth: true)
    }

    public func refresh() async throws {
        guard let refreshToken else { throw URLError(.userAuthenticationRequired) }
        let data = try await post(path: "/v1/auth/refresh", body: ["refresh_token": refreshToken], auth: false)
        let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        if let access = obj?["access_token"] as? String { accessToken = access }
        if let refresh = obj?["refresh_token"] as? String { self.refreshToken = refresh }
    }

    private func get(path: String, auth: Bool) async throws -> Data {
        var req = URLRequest(url: url(path))
        req.httpMethod = "GET"
        if auth, let accessToken {
            req.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        }
        return try await send(req)
    }

    private func post(path: String, body: [String: String], auth: Bool) async throws -> Data {
        let data = try JSONSerialization.data(withJSONObject: body)
        return try await post(path: path, data: data, auth: auth)
    }

    private func post(path: String, data: Data, auth: Bool) async throws -> Data {
        var req = URLRequest(url: url(path))
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if auth, let accessToken {
            req.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        }
        req.httpBody = data
        return try await send(req)
    }

    private func send(_ req: URLRequest) async throws -> Data {
        let (out, res) = try await URLSession.shared.data(for: req)
        guard let http = res as? HTTPURLResponse else { throw URLError(.badServerResponse) }
        if http.statusCode == 401 {
            try await refresh()
            var retry = req
            if let accessToken {
                retry.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
            }
            let (out2, res2) = try await URLSession.shared.data(for: retry)
            guard let http2 = res2 as? HTTPURLResponse, (200..<300).contains(http2.statusCode) else {
                throw URLError(.userAuthenticationRequired)
            }
            return out2
        }
        guard (200..<300).contains(http.statusCode) else { throw URLError(.badServerResponse) }
        return out
    }

    private func url(_ path: String) -> URL {
        // Paths already include /v1/...
        URL(string: path, relativeTo: baseURL)!.absoluteURL
    }
}

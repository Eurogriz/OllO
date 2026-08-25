import Foundation

public actor OlloClient {
    public var baseURL: URL
    public var accessToken: String?

    public init(baseURL: URL) {
        self.baseURL = baseURL
    }

    public func requestOTP(phone: String) async throws -> Data {
        try await post(path: "/v1/auth/request-otp", body: ["phone_e164": phone], auth: false)
    }

    public func sendEnvelopes(json: Data) async throws -> Data {
        try await post(path: "/v1/envelopes", data: json, auth: true)
    }

    private func post(path: String, body: [String: String], auth: Bool) async throws -> Data {
        let data = try JSONSerialization.data(withJSONObject: body)
        return try await post(path: path, data: data, auth: auth)
    }

    private func post(path: String, data: Data, auth: Bool) async throws -> Data {
        var req = URLRequest(url: baseURL.appendingPathComponent(path))
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if auth, let accessToken {
            req.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        }
        req.httpBody = data
        let (out, res) = try await URLSession.shared.data(for: req)
        guard let http = res as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            throw URLError(.badServerResponse)
        }
        return out
    }
}

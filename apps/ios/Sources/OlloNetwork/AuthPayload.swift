import Foundation

/// Parse / assemble auth JSON. Never invents `registration_id`, prekey ids,
/// or identity keys — those come only from a bound libsignal engine.
public enum AuthPayload {
    public enum Error: Swift.Error, Equatable {
        case malformed
        case missingDevice
    }

    public static func parseAuthChallenge(_ data: Data) throws -> (challengeId: String, nonce: String) {
        guard let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw Error.malformed
        }
        guard let challengeId = obj["challenge_id"] as? String, !challengeId.isEmpty,
              let nonce = obj["nonce"] as? String, !nonce.isEmpty
        else {
            throw Error.malformed
        }
        return (challengeId, nonce)
    }

    public static func parseOtpChallenge(_ data: Data) throws -> (challengeId: String, devOtp: String?) {
        guard let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw Error.malformed
        }
        guard let challengeId = obj["challenge_id"] as? String, !challengeId.isEmpty else {
            throw Error.malformed
        }
        let dev = obj["dev_otp"] as? String
        return (challengeId, (dev?.isEmpty == false) ? dev : nil)
    }

    public static func parseSession(_ data: Data) throws -> AuthSession {
        guard let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw Error.malformed
        }
        guard let user = obj["user"] as? [String: Any] else { throw Error.malformed }
        guard let userId = user["id"] as? String, !userId.isEmpty else { throw Error.malformed }
        guard let deviceId = obj["device_id"] as? String, !deviceId.isEmpty else { throw Error.malformed }
        guard let access = obj["access_token"] as? String, !access.isEmpty else { throw Error.malformed }
        guard let refresh = obj["refresh_token"] as? String, !refresh.isEmpty else { throw Error.malformed }
        let username = user["username"] as? String
        return AuthSession(
            userId: userId,
            username: (username?.isEmpty == false) ? username : nil,
            deviceId: deviceId,
            access: access,
            refresh: refresh
        )
    }

    public static func parseRefresh(_ data: Data) throws -> (access: String, refresh: String) {
        guard let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw Error.malformed
        }
        guard let access = obj["access_token"] as? String, !access.isEmpty else { throw Error.malformed }
        guard let refresh = obj["refresh_token"] as? String, !refresh.isEmpty else { throw Error.malformed }
        return (access, refresh)
    }

    /// Wraps a bound-engine device object. Incomplete JSON is rejected; fields
    /// are never filled in here.
    public static func verifyBody(
        challengeId: String,
        otp: String,
        deviceJson: String,
        registrationLock: String? = nil
    ) throws -> Data {
        guard let deviceData = deviceJson.data(using: .utf8),
              let device = try JSONSerialization.jsonObject(with: deviceData) as? [String: Any]
        else {
            throw Error.missingDevice
        }
        guard device["identity_key_x25519"] is String,
              device["identity_key_ed25519"] is String,
              device["registration_id"] is NSNumber || device["registration_id"] is Int,
              device["signed_prekey"] is [String: Any],
              device["one_time_prekeys"] is [Any]
        else {
            throw Error.missingDevice
        }
        var body: [String: Any] = [
            "challenge_id": challengeId,
            "otp": otp,
            "device": device,
        ]
        if let registrationLock, !registrationLock.isEmpty {
            body["registration_lock"] = registrationLock
        }
        return try JSONSerialization.data(withJSONObject: body)
    }

    public static func registerKeyBody(
        challengeId: String,
        signature: String,
        deviceJson: String,
        registrationLock: String? = nil
    ) throws -> Data {
        guard let deviceData = deviceJson.data(using: .utf8),
              let device = try JSONSerialization.jsonObject(with: deviceData) as? [String: Any]
        else {
            throw Error.missingDevice
        }
        guard device["identity_key_x25519"] is String,
              device["identity_key_ed25519"] is String,
              device["registration_id"] is NSNumber || device["registration_id"] is Int,
              device["signed_prekey"] is [String: Any],
              device["one_time_prekeys"] is [Any]
        else {
            throw Error.missingDevice
        }
        var body: [String: Any] = [
            "challenge_id": challengeId,
            "signature": signature,
            "device": device,
        ]
        if let registrationLock, !registrationLock.isEmpty {
            body["registration_lock"] = registrationLock
        }
        return try JSONSerialization.data(withJSONObject: body)
    }
}

public struct AuthSession: Sendable, Equatable {
    public var userId: String
    public var username: String?
    public var deviceId: String
    public var access: String
    public var refresh: String

    public init(userId: String, username: String?, deviceId: String, access: String, refresh: String) {
        self.userId = userId
        self.username = username
        self.deviceId = deviceId
        self.access = access
        self.refresh = refresh
    }
}

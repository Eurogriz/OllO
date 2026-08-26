import Foundation

/// Access / refresh live in a dedicated wrapped slot. Never written into backups.
public struct SessionSecrets: Sendable, Equatable {
    public var userId: String
    public var deviceId: String
    public var access: String
    public var refresh: String

    public init(userId: String, deviceId: String, access: String, refresh: String) {
        self.userId = userId
        self.deviceId = deviceId
        self.access = access
        self.refresh = refresh
    }
}

public final class SessionVault: @unchecked Sendable {
    public static let key = "session.v1"
    private let store: IdentityStore
    private let wrapKey: Data

    public init(store: IdentityStore, wrapKey: Data) {
        self.store = store
        self.wrapKey = wrapKey
    }

    public func save(_ secrets: SessionSecrets) throws {
        try store.put(
            wrapKey: wrapKey,
            key: Self.key,
            plaintext: try BlobMap.encode([
                "userId": Data(secrets.userId.utf8),
                "deviceId": Data(secrets.deviceId.utf8),
                "access": Data(secrets.access.utf8),
                "refresh": Data(secrets.refresh.utf8),
            ])
        )
    }

    public func load() throws -> SessionSecrets? {
        guard let raw = try store.get(wrapKey: wrapKey, key: Self.key) else { return nil }
        let map = try BlobMap.decode(raw)
        guard
            let userId = string(map["userId"]),
            let deviceId = string(map["deviceId"]),
            let access = string(map["access"]),
            let refresh = string(map["refresh"])
        else { return nil }
        return SessionSecrets(userId: userId, deviceId: deviceId, access: access, refresh: refresh)
    }

    public func clear() throws {
        try store.remove(key: Self.key)
    }

    private func string(_ data: Data?) -> String? {
        guard let data else { return nil }
        return String(data: data, encoding: .utf8)
    }
}

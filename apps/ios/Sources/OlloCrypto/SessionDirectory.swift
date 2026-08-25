import Foundation

/// Encrypted directory of opaque libsignal session records and remote
/// identity fingerprints. This type does not ratcheting-encrypt: it only
/// stores what SessionCipher produces, under AES-GCM.
public final class SessionDirectory: @unchecked Sendable {
    public enum IdentityDecision: String, Sendable {
        case new
        case unchanged
        case changed
    }

    public struct Address: Hashable, Sendable {
        public var userId: String
        public var deviceId: String

        public init(userId: String, deviceId: String) {
            self.userId = userId
            self.deviceId = deviceId
        }

        public var key: String { "\(userId):\(deviceId)" }
    }

    private let store: IdentityStore
    private let wrapKey: Data
    public var localUserId: String
    public var localDeviceId: String

    public init(
        store: IdentityStore,
        wrapKey: Data,
        localUserId: String = "",
        localDeviceId: String = ""
    ) {
        self.store = store
        self.wrapKey = wrapKey
        self.localUserId = localUserId
        self.localDeviceId = localDeviceId
    }

    public func hasSession(_ address: Address) throws -> Bool {
        try sessions()[address.key] != nil
    }

    public func loadSession(_ address: Address) throws -> Data? {
        try sessions()[address.key]
    }

    public func saveSession(_ address: Address, record: Data) throws {
        var map = try sessions()
        map[address.key] = record
        try persist(.sessions, map)
    }

    public func deleteSession(_ address: Address) throws {
        var map = try sessions()
        map.removeValue(forKey: address.key)
        try persist(.sessions, map)
    }

    public func planFetch(targetUserId: String, targetDeviceId: String) throws -> EnvelopePlanner.KeyPlan {
        EnvelopePlanner.planKeyFetch(
            localUserId: localUserId,
            localDeviceId: localDeviceId,
            targetUserId: targetUserId,
            targetDeviceId: targetDeviceId,
            hasSession: try hasSession(Address(userId: targetUserId, deviceId: targetDeviceId))
        )
    }

    public func noteRemoteIdentity(_ address: Address, identityX25519: Data) throws -> IdentityDecision {
        var map = try identities()
        guard let prev = map[address.key] else {
            map[address.key] = identityX25519
            try persist(.knownIdentities, map)
            return .new
        }
        if prev == identityX25519 { return .unchanged }
        return .changed
    }

    /// Overwrite only after the user re-verifies a changed safety number.
    public func replaceRemoteIdentity(_ address: Address, identityX25519: Data) throws {
        var map = try identities()
        map[address.key] = identityX25519
        try persist(.knownIdentities, map)
    }

    public func wipe() {
        store.wipe()
    }

    private func sessions() throws -> [String: Data] {
        try load(.sessions)
    }

    private func identities() throws -> [String: Data] {
        try load(.knownIdentities)
    }

    private func load(_ slot: IdentityStore.Slot) throws -> [String: Data] {
        guard let raw = try store.get(wrapKey: wrapKey, slot: slot) else { return [:] }
        return try BlobMap.decode(raw)
    }

    private func persist(_ slot: IdentityStore.Slot, _ map: [String: Data]) throws {
        try store.put(wrapKey: wrapKey, slot: slot, plaintext: BlobMap.encode(map))
    }
}

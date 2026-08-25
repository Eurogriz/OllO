import Foundation

/// Durable opaque store for official libsignal records. Does not implement a
/// Double Ratchet — only persists what SessionCipher produces under AES-GCM.
public final class ProtocolStore: @unchecked Sendable {
    public let store: IdentityStore
    public let sessions: SessionDirectory
    public let messages: MessageLog
    private let wrapKey: Data

    public init(
        store: IdentityStore,
        wrapKey: Data,
        localUserId: String = "",
        localDeviceId: String = ""
    ) {
        self.store = store
        self.wrapKey = wrapKey
        self.sessions = SessionDirectory(
            store: store,
            wrapKey: wrapKey,
            localUserId: localUserId,
            localDeviceId: localDeviceId
        )
        self.messages = MessageLog(store: store, wrapKey: wrapKey)
    }

    public func storeLocalIdentity(record: Data, registrationId: Int) throws {
        guard (1...0x3FFF).contains(registrationId) else { throw StoreError.registrationId }
        try persist(.identity, [
            "record": record,
            "registration_id": be32(UInt32(registrationId)),
        ])
    }

    public func loadLocalIdentity() throws -> Data? {
        try loadMap(.identity)["record"]
    }

    public func registrationId() throws -> Int? {
        guard let raw = try loadMap(.identity)["registration_id"], raw.count == 4 else { return nil }
        let n = raw.withUnsafeBytes { buf -> UInt32 in
            let b = buf.bindMemory(to: UInt8.self)
            return (UInt32(b[0]) << 24) | (UInt32(b[1]) << 16) | (UInt32(b[2]) << 8) | UInt32(b[3])
        }
        return Int(n)
    }

    public func storePreKey(id: Int, record: Data) throws {
        var map = try loadMap(.preKeys)
        map[String(id)] = record
        try persist(.preKeys, map)
    }

    public func loadPreKey(id: Int) throws -> Data? {
        try loadMap(.preKeys)[String(id)]
    }

    public func removePreKey(id: Int) throws {
        var map = try loadMap(.preKeys)
        map.removeValue(forKey: String(id))
        try persist(.preKeys, map)
    }

    public func storeSignedPreKey(id: Int, record: Data) throws {
        var map = try loadMap(.signedPreKeys)
        map[String(id)] = record
        try persist(.signedPreKeys, map)
    }

    public func loadSignedPreKey(id: Int) throws -> Data? {
        try loadMap(.signedPreKeys)[String(id)]
    }

    public func saveThreads(_ index: ThreadIndex) throws {
        try store.put(wrapKey: wrapKey, slot: .threads, plaintext: try index.encode())
    }

    public func loadThreads() throws -> ThreadIndex {
        guard let raw = try store.get(wrapKey: wrapKey, slot: .threads) else { return ThreadIndex() }
        return try ThreadIndex.decode(raw)
    }

    public func saveOutboxItem(id: String, payload: Data) throws {
        var map = try loadMap(.outbox)
        map[id] = payload
        try persist(.outbox, map)
    }

    public func loadOutbox() throws -> [String: Data] {
        try loadMap(.outbox)
    }

    public func removeOutboxItem(id: String) throws {
        var map = try loadMap(.outbox)
        map.removeValue(forKey: id)
        try persist(.outbox, map)
    }

    public func planFetch(targetUserId: String, targetDeviceId: String) throws -> EnvelopePlanner.KeyPlan {
        try sessions.planFetch(targetUserId: targetUserId, targetDeviceId: targetDeviceId)
    }

    public func wipe() {
        store.wipe()
    }

    public enum StoreError: Error {
        case registrationId
    }

    private func loadMap(_ slot: IdentityStore.Slot) throws -> [String: Data] {
        guard let raw = try store.get(wrapKey: wrapKey, slot: slot) else { return [:] }
        return try BlobMap.decode(raw)
    }

    private func persist(_ slot: IdentityStore.Slot, _ map: [String: Data]) throws {
        try store.put(wrapKey: wrapKey, slot: slot, plaintext: try BlobMap.encode(map))
    }

    private func be32(_ n: UInt32) -> Data {
        Data([
            UInt8((n >> 24) & 0xFF),
            UInt8((n >> 16) & 0xFF),
            UInt8((n >> 8) & 0xFF),
            UInt8(n & 0xFF),
        ])
    }
}

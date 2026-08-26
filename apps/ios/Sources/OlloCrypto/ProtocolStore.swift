import Foundation

/// Durable opaque store for official libsignal records. Does not implement a
/// Double Ratchet — only persists what SessionCipher produces under AES-GCM.
public final class ProtocolStore: @unchecked Sendable {
    public let store: IdentityStore
    public let sessions: SessionDirectory
    public let messages: MessageLog
    public let sessionVault: SessionVault
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
        self.sessionVault = SessionVault(store: store, wrapKey: wrapKey)
        self.accountVault = AccountVault(store: store, wrapKey: wrapKey)
    }

    public let accountVault: AccountVault

    public func storeLocalIdentity(
        record: Data,
        registrationId: Int,
        extras: [String: Data] = [:]
    ) throws {
        guard (1...0x3FFF).contains(registrationId) else { throw StoreError.registrationId }
        var map: [String: Data] = [
            "record": record,
            "registration_id": be32(UInt32(registrationId)),
        ]
        for (k, v) in extras { map[k] = v }
        try persist(.identity, map)
    }

    public func loadLocalIdentity() throws -> Data? {
        try loadMap(.identity)["record"]
    }

    public func loadIdentityField(_ name: String) throws -> Data? {
        try loadMap(.identity)[name]
    }

    public func preKeyIds() throws -> [Int] {
        try loadMap(.preKeys).keys.compactMap { Int($0) }.sorted()
    }

    public func signedPreKeyIds() throws -> [Int] {
        try loadMap(.signedPreKeys).keys.compactMap { Int($0) }.sorted()
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

    /// Drop retired signed prekeys beyond the keep-last-2 window.
    public func pruneSignedPreKeys(currentId: Int) throws {
        let map = try loadMap(.signedPreKeys)
        let storedIds = map.keys.compactMap { Int($0) }
        let keep = Set(EnvelopePlanner.keepSignedPrekeyIds(currentId: currentId, storedIds: storedIds))
        var next: [String: Data] = [:]
        for (k, v) in map {
            guard let id = Int(k), keep.contains(id) else { continue }
            next[k] = v
        }
        try persist(.signedPreKeys, next)
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

    public func rememberEnvelope(_ envelopeId: String) throws -> EnvelopePlanner.ReplayDecision {
        var map = try loadMap(.replay)
        var ids: [String] = []
        if let raw = map["ids"], let text = String(data: raw, encoding: .utf8) {
            ids = text.split(separator: "\n", omittingEmptySubsequences: true).map(String.init)
        }
        let decision = EnvelopePlanner.rememberEnvelope(&ids, envelopeId: envelopeId)
        if decision == .accept {
            map["ids"] = Data(ids.joined(separator: "\n").utf8)
            try persist(.replay, map)
        }
        return decision
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

import Foundation

/// Long-term account Ed25519 lives in its own wrapped slot. Generating a new
/// `AccountKey` on every unsigned launch would mint a new account each tap.
public final class AccountVault: @unchecked Sendable {
    private let store: IdentityStore
    private let wrapKey: Data

    public init(store: IdentityStore, wrapKey: Data) {
        self.store = store
        self.wrapKey = wrapKey
    }

    public func save(_ key: AccountKey) throws {
        try store.put(
            wrapKey: wrapKey,
            slot: .account,
            plaintext: try BlobMap.encode([
                "seed": key.privateKey.rawRepresentation,
                "public": key.publicKey,
            ])
        )
    }

    public func load() throws -> AccountKey? {
        guard let raw = try store.get(wrapKey: wrapKey, slot: .account) else { return nil }
        let map = try BlobMap.decode(raw)
        guard let seed = map["seed"] else { return nil }
        return try AccountKey(rawPrivateKey: seed)
    }

    public func getOrCreate() throws -> AccountKey {
        if let existing = try load() { return existing }
        let next = AccountKey()
        try save(next)
        return next
    }
}

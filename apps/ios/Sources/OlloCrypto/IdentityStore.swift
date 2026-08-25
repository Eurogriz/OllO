import Foundation

/// Encrypted identity / session / outbox blobs. The wrapping key never
/// lives next to the ciphertext: on device it comes from Keychain;
/// tests inject a software key.
///
/// Wipe drops every secret. Call this on logout, device revoke, and remote wipe.
public final class IdentityStore: @unchecked Sendable {
    private var kv: [String: Data] = [:]

    public init() {}

    public func put(wrapKey: Data, slot: Slot, plaintext: Data) throws {
        kv[slot.rawValue] = try AesGcmWrap.seal(key: wrapKey, plaintext: plaintext)
    }

    public func get(wrapKey: Data, slot: Slot) throws -> Data? {
        guard let blob = kv[slot.rawValue] else { return nil }
        return try AesGcmWrap.open(key: wrapKey, blob: blob)
    }

    @discardableResult
    public func wipe() -> Int {
        let n = kv.count
        for k in kv.keys {
            kv[k]?.resetBytes(in: 0..<(kv[k]?.count ?? 0))
        }
        kv.removeAll()
        return n
    }

    public var isEmpty: Bool { kv.isEmpty }

    public enum Slot: String, Sendable {
        case identity = "identity.v1"
        case sessions = "sessions.v1"
        case outbox = "outbox.v1"
        case senderKeys = "senderkeys.v1"
        case knownIdentities = "known.v1"
    }
}

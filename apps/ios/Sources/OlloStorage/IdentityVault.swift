import Foundation
import OlloCrypto
import Security

/// Identity / session blobs sealed with AES-GCM. The wrapping key lives in
/// Keychain (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`) and is never
/// written next to the ciphertext.
public final class IdentityVault: @unchecked Sendable {
    public static let wrapAccount = "ollo.vault.wrap.v1"
    private var kv: [String: Data]
    private let directory: URL

    public init(directory: URL, kv: [String: Data] = [:]) {
        self.directory = directory
        self.kv = kv
    }

    public func wrappingKey() throws -> Data {
        if let existing = try? KeychainStore.get(account: Self.wrapAccount), existing.count == 32 {
            return existing
        }
        var raw = Data(count: 32)
        let status = raw.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        guard status == errSecSuccess else { throw NSError(domain: "ollo.rng", code: Int(status)) }
        try KeychainStore.set(raw, account: Self.wrapAccount)
        return raw
    }

    public func put(slot: Slot, plaintext: Data) throws {
        let key = try wrappingKey()
        kv[slot.rawValue] = try AesGcmWrap.seal(key: key, plaintext: plaintext)
        try persist()
    }

    public func get(slot: Slot) throws -> Data? {
        guard let blob = kv[slot.rawValue] else { return nil }
        return try AesGcmWrap.open(key: try wrappingKey(), blob: blob)
    }

    public func wipe() throws {
        for k in kv.keys {
            kv[k]?.resetBytes(in: 0..<(kv[k]?.count ?? 0))
        }
        kv.removeAll()
        KeychainStore.delete(account: Self.wrapAccount)
        let file = directory.appendingPathComponent("vault.dat")
        try? FileManager.default.removeItem(at: file)
    }

    public var isEmpty: Bool { kv.isEmpty }

    public enum Slot: String {
        case identity = "identity.v1"
        case sessions = "sessions.v1"
        case outbox = "outbox.v1"
        case senderKeys = "senderkeys.v1"
        case knownIdentities = "known.v1"
    }

    private func persist() throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let file = directory.appendingPathComponent("vault.dat")
        let payload = try JSONEncoder().encode(kv.mapValues { $0.base64EncodedString() })
        try payload.write(to: file, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
    }
}

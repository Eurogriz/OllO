import Foundation

/// Encrypted identity / session / outbox / prekey blobs. The wrapping key never
/// lives next to the ciphertext: on device it comes from Keychain;
/// tests inject a software key.
///
/// Optional `directory` persists already-wrapped files (one per key).
/// Wipe shreds memory and files.
public final class IdentityStore: @unchecked Sendable {
    private var kv: [String: Data] = [:]
    private let directory: URL?

    public init(directory: URL? = nil) {
        self.directory = directory
        if let directory {
            try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            if let files = try? FileManager.default.contentsOfDirectory(
                at: directory,
                includingPropertiesForKeys: nil
            ) {
                for f in files where !f.lastPathComponent.hasSuffix(".tmp") {
                    if let data = try? Data(contentsOf: f) {
                        kv[f.lastPathComponent] = data
                    }
                }
            }
        }
    }

    public func put(wrapKey: Data, slot: Slot, plaintext: Data) throws {
        try put(wrapKey: wrapKey, key: slot.rawValue, plaintext: plaintext)
    }

    public func put(wrapKey: Data, key: String, plaintext: Data) throws {
        try assertSafeStoreKey(key)
        let sealed = try AesGcmWrap.seal(key: wrapKey, plaintext: plaintext)
        kv[key] = sealed
        try writeFile(key: key, sealed: sealed)
    }

    public func get(wrapKey: Data, slot: Slot) throws -> Data? {
        try get(wrapKey: wrapKey, key: slot.rawValue)
    }

    public func get(wrapKey: Data, key: String) throws -> Data? {
        try assertSafeStoreKey(key)
        guard let blob = kv[key] else { return nil }
        return try AesGcmWrap.open(key: wrapKey, blob: blob)
    }

    public func remove(key: String) throws {
        try assertSafeStoreKey(key)
        kv[key]?.resetBytes(in: 0..<(kv[key]?.count ?? 0))
        kv.removeValue(forKey: key)
        if let directory {
            try? FileManager.default.removeItem(at: directory.appendingPathComponent(key))
        }
    }

    public func keys(prefix: String = "") -> [String] {
        kv.keys.filter { $0.hasPrefix(prefix) }.sorted()
    }

    @discardableResult
    public func wipe() -> Int {
        let n = kv.count
        for k in kv.keys {
            kv[k]?.resetBytes(in: 0..<(kv[k]?.count ?? 0))
        }
        kv.removeAll()
        if let directory, let files = try? FileManager.default.contentsOfDirectory(
            at: directory,
            includingPropertiesForKeys: nil
        ) {
            for f in files {
                if let data = try? Data(contentsOf: f), !data.isEmpty {
                    let shred = Data(count: min(data.count, 4096))
                    try? shred.write(to: f, options: .atomic)
                }
                try? FileManager.default.removeItem(at: f)
            }
        }
        return n
    }

    public var isEmpty: Bool { kv.isEmpty }

    public enum Slot: String, Sendable {
        case identity = "identity.v1"
        case sessions = "sessions.v1"
        case outbox = "outbox.v1"
        case senderKeys = "senderkeys.v1"
        case knownIdentities = "known.v1"
        case preKeys = "prekeys.v1"
        case signedPreKeys = "signedprekeys.v1"
        case threads = "threads.v1"
        case replay = "replay.v1"
        case account = "account.v1"
    }

    private func writeFile(key: String, sealed: Data) throws {
        guard let directory else { return }
        let target = directory.appendingPathComponent(key)
        let tmp = directory.appendingPathComponent("\(key).tmp")
        try sealed.write(to: tmp, options: .atomic)
        if FileManager.default.fileExists(atPath: target.path) {
            try FileManager.default.removeItem(at: target)
        }
        try FileManager.default.moveItem(at: tmp, to: target)
    }
}

func assertSafeStoreKey(_ key: String) throws {
    if key.isEmpty { throw StoreKeyError.empty }
    if key.contains("/") || key.contains("\\") || key.contains("\0") || key.contains("..") {
        throw StoreKeyError.unsafe
    }
}

enum StoreKeyError: Error {
    case empty
    case unsafe
}

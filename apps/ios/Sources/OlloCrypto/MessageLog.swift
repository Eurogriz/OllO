import Foundation

/// Sealed local history. Bodies are already-decrypted plaintext wrapped with
/// the device key — the server never supplies them.
public struct LocalMessage: Sendable, Equatable {
    public var clientId: String
    public var threadId: String
    public var senderId: String
    public var sentAt: Int64
    public var status: String
    public var body: Data
    public var expiresAt: Int64?

    public init(
        clientId: String,
        threadId: String,
        senderId: String,
        sentAt: Int64,
        status: String,
        body: Data,
        expiresAt: Int64? = nil
    ) {
        self.clientId = clientId
        self.threadId = threadId
        self.senderId = senderId
        self.sentAt = sentAt
        self.status = status
        self.body = body
        self.expiresAt = expiresAt
    }
}

public final class MessageLog: @unchecked Sendable {
    public static let prefix = "msg."
    private let store: IdentityStore
    private let wrapKey: Data

    public init(store: IdentityStore, wrapKey: Data) {
        self.store = store
        self.wrapKey = wrapKey
    }

    public func put(_ message: LocalMessage) throws {
        try store.put(
            wrapKey: wrapKey,
            key: key(message.clientId),
            plaintext: try LocalMessageCodec.encode(message)
        )
    }

    public func get(clientId: String) throws -> LocalMessage? {
        guard let raw = try store.get(wrapKey: wrapKey, key: key(clientId)) else { return nil }
        return try LocalMessageCodec.decode(raw)
    }

    public func list(threadId: String) throws -> [LocalMessage] {
        try store.keys(prefix: Self.prefix).compactMap { k in
            guard let raw = try store.get(wrapKey: wrapKey, key: k) else { return nil }
            return try LocalMessageCodec.decode(raw)
        }
        .filter { $0.threadId == threadId }
        .sorted { $0.sentAt < $1.sentAt }
    }

    public func expire(now: Int64) throws -> Int {
        var n = 0
        for k in store.keys(prefix: Self.prefix) {
            guard let raw = try store.get(wrapKey: wrapKey, key: k) else { continue }
            let msg = try LocalMessageCodec.decode(raw)
            if let exp = msg.expiresAt, exp <= now {
                try store.remove(key: k)
                n += 1
            }
        }
        return n
    }

    private func key(_ clientId: String) throws -> String {
        try assertSafeStoreKey(clientId)
        return Self.prefix + clientId
    }
}

public enum LocalMessageCodec {
    private static let magic: [UInt8] = [0x4F, 0x4C, 0x4D, 0x32]

    public static func encode(_ message: LocalMessage) throws -> Data {
        var out = Data(magic)
        out.append(utf(message.clientId))
        out.append(utf(message.threadId))
        out.append(utf(message.senderId))
        out.append(i64(message.sentAt))
        out.append(i64(message.expiresAt ?? 0))
        out.append(utf(message.status))
        out.append(contentsOf: [
            UInt8((UInt32(message.body.count) >> 24) & 0xFF),
            UInt8((UInt32(message.body.count) >> 16) & 0xFF),
            UInt8((UInt32(message.body.count) >> 8) & 0xFF),
            UInt8(UInt32(message.body.count) & 0xFF),
        ])
        out.append(message.body)
        return out
    }

    public static func decode(_ bytes: Data) throws -> LocalMessage {
        guard bytes.count >= 8 else { throw CodecError.tooShort }
        var i = bytes.startIndex
        let mag = [UInt8](bytes[i..<(i + 4)])
        i += 4
        guard mag == magic else { throw CodecError.badMagic }
        let clientId = try readUtf(bytes, &i)
        let threadId = try readUtf(bytes, &i)
        let senderId = try readUtf(bytes, &i)
        let sentAt = try readI64(bytes, &i)
        let exp = try readI64(bytes, &i)
        let status = try readUtf(bytes, &i)
        guard bytes.distance(from: i, to: bytes.endIndex) >= 4 else { throw CodecError.tooShort }
        let n = Int(
            (UInt32(bytes[i]) << 24) | (UInt32(bytes[i + 1]) << 16) | (UInt32(bytes[i + 2]) << 8) | UInt32(bytes[i + 3])
        )
        i += 4
        guard n >= 0 && n <= 8 * 1024 * 1024 else { throw CodecError.bodyTooLarge }
        guard bytes.distance(from: i, to: bytes.endIndex) >= n else { throw CodecError.tooShort }
        let body = Data(bytes[i..<(i + n)])
        return LocalMessage(
            clientId: clientId,
            threadId: threadId,
            senderId: senderId,
            sentAt: sentAt,
            status: status,
            body: body,
            expiresAt: exp == 0 ? nil : exp
        )
    }

    public enum CodecError: Error {
        case tooShort
        case badMagic
        case bodyTooLarge
    }

    private static func utf(_ s: String) -> Data {
        let b = Data(s.utf8)
        return Data([UInt8(b.count >> 8), UInt8(b.count & 0xFF)]) + b
    }

    private static func i64(_ n: Int64) -> Data {
        var out = Data(count: 8)
        var v = UInt64(bitPattern: n).bigEndian
        withUnsafeBytes(of: &v) { out.replaceSubrange(0..<8, with: $0) }
        return out
    }

    private static func readUtf(_ bytes: Data, _ i: inout Data.Index) throws -> String {
        guard bytes.distance(from: i, to: bytes.endIndex) >= 2 else { throw CodecError.tooShort }
        let n = Int((UInt16(bytes[i]) << 8) | UInt16(bytes[i + 1]))
        i += 2
        guard bytes.distance(from: i, to: bytes.endIndex) >= n else { throw CodecError.tooShort }
        let slice = bytes[i..<(i + n)]
        i += n
        guard let s = String(data: Data(slice), encoding: .utf8) else { throw CodecError.tooShort }
        return s
    }

    private static func readI64(_ bytes: Data, _ i: inout Data.Index) throws -> Int64 {
        guard bytes.distance(from: i, to: bytes.endIndex) >= 8 else { throw CodecError.tooShort }
        var v: UInt64 = 0
        for _ in 0..<8 {
            v = (v << 8) | UInt64(bytes[i])
            i += 1
        }
        return Int64(bitPattern: v)
    }
}

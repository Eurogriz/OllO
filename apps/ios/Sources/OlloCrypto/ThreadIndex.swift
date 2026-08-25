import Foundation

/// Local chat list. Never seeded with demo contacts. Previews are whatever
/// the device already decrypted — the server never supplies them.
public struct ChatThread: Sendable, Equatable {
    public var id: String
    public var title: String
    public var preview: String
    public var peerUserId: String?
    public var groupId: String?
    public var archived: Bool
    public var muted: Bool

    public init(
        id: String,
        title: String,
        preview: String = "",
        peerUserId: String? = nil,
        groupId: String? = nil,
        archived: Bool = false,
        muted: Bool = false
    ) {
        self.id = id
        self.title = title
        self.preview = preview
        self.peerUserId = peerUserId
        self.groupId = groupId
        self.archived = archived
        self.muted = muted
    }

    public func encode() throws -> Data {
        var flags: UInt8 = 0
        if archived { flags |= 1 }
        if muted { flags |= 2 }
        return try BlobMap.encode([
            "title": Data(title.utf8),
            "preview": Data(preview.utf8),
            "peer": Data((peerUserId ?? "").utf8),
            "group": Data((groupId ?? "").utf8),
            "flags": Data([flags]),
        ])
    }

    public static func decode(id: String, raw: Data) throws -> ChatThread {
        let m = try BlobMap.decode(raw)
        let flags = Int(m["flags"]?.first ?? 0)
        let peer = String(data: m["peer"] ?? Data(), encoding: .utf8) ?? ""
        let group = String(data: m["group"] ?? Data(), encoding: .utf8) ?? ""
        return ChatThread(
            id: id,
            title: String(data: m["title"] ?? Data(), encoding: .utf8) ?? id,
            preview: String(data: m["preview"] ?? Data(), encoding: .utf8) ?? "",
            peerUserId: peer.isEmpty ? nil : peer,
            groupId: group.isEmpty ? nil : group,
            archived: flags & 1 != 0,
            muted: flags & 2 != 0
        )
    }
}

public final class ThreadIndex: @unchecked Sendable {
    private var threads: [String: ChatThread] = [:]
    private var order: [String] = []

    public init() {}

    public func visible() -> [ChatThread] {
        order.compactMap { id in
            guard let t = threads[id], !t.archived else { return nil }
            return t
        }
    }

    public func snapshot() -> [ChatThread] {
        order.compactMap { threads[$0] }
    }

    public func upsert(_ thread: ChatThread) {
        if threads[thread.id] == nil {
            order.append(thread.id)
        }
        threads[thread.id] = thread
    }

    public func archive(_ id: String, archived: Bool = true) {
        guard var t = threads[id] else { return }
        t.archived = archived
        threads[id] = t
    }

    public func wipe() {
        threads.removeAll()
        order.removeAll()
    }

    public var isEmpty: Bool { visible().isEmpty }

    public func encode() throws -> Data {
        var map: [String: Data] = [:]
        for (id, thread) in threads {
            map[id] = try thread.encode()
        }
        return try BlobMap.encode(map)
    }

    public static func decode(_ bytes: Data) throws -> ThreadIndex {
        let index = ThreadIndex()
        for (id, raw) in try BlobMap.decode(bytes) {
            index.upsert(try ChatThread.decode(id: id, raw: raw))
        }
        return index
    }
}

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
}

import Foundation

/// In-memory access/refresh plus the wrapped SessionVault. Tokens never go
/// into backups. A failed refresh wipes identity, sessions, and history.
public final class SessionController: @unchecked Sendable {
    private let proto: ProtocolStore
    public private(set) var secrets: SessionSecrets?

    public init(proto: ProtocolStore) {
        self.proto = proto
    }

    public func access() -> String? { secrets?.access }

    public func refresh() -> String? { secrets?.refresh }

    public func restore() throws -> SessionSecrets? {
        secrets = try proto.sessionVault.load()
        return secrets
    }

    public func save(_ next: SessionSecrets) throws {
        try proto.sessionVault.save(next)
        secrets = next
    }

    public func applyRefresh(access: String, refresh: String) throws -> Bool {
        guard var cur = secrets else { return false }
        cur.access = access
        cur.refresh = refresh
        try save(cur)
        return true
    }

    public func onUnauthorized(refreshSucceeded: Bool) -> EnvelopePlanner.AuthFailure {
        let action = EnvelopePlanner.afterUnauthorized(refreshSucceeded: refreshSucceeded)
        if action == .wipe { wipe() }
        return action
    }

    public func wipe() {
        secrets = nil
        proto.wipe()
    }
}

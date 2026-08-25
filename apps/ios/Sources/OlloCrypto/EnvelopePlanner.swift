import Foundation

/// Offline-first outbound planner. Must stay in lockstep with
/// `packages/shared/src/outbox.ts`. Production encrypt still uses libsignal;
/// this only decides whether to consume a one-time prekey.
public enum EnvelopePlanner {
    public static let maxAttempts = 8
    public static let baseDelayMs: Int = 1500

    public enum Status: String, Sendable {
        case draft
        case pending
        case encrypted
        case uploading
        case sent
        case delivered
        case read
        case failed
        case retrying
    }

    public enum KeyPlan: String, Sendable {
        case skipSelf = "skip-self"
        case useSession = "use-session"
        case consumeBundle = "consume-bundle"
    }

    public struct OutboxItem: Sendable {
        public var id: String
        public var status: Status
        public var attempts: Int

        public init(id: String, status: Status, attempts: Int) {
            self.id = id
            self.status = status
            self.attempts = attempts
        }
    }

    public static func nextRetryDelayMs(attempts: Int) -> Int {
        let exp = min(6, max(0, attempts))
        return baseDelayMs * (1 << exp)
    }

    public static func onSendFailure(_ item: OutboxItem) -> OutboxItem {
        var next = item
        next.attempts += 1
        next.status = next.attempts >= maxAttempts ? .failed : .retrying
        return next
    }

    /// Never consume a one-time prekey when a Double Ratchet session exists.
    /// Never address the sending device.
    public static func planKeyFetch(
        localUserId: String,
        localDeviceId: String,
        targetUserId: String,
        targetDeviceId: String,
        hasSession: Bool
    ) -> KeyPlan {
        if localUserId == targetUserId && localDeviceId == targetDeviceId {
            return .skipSelf
        }
        return hasSession ? .useSession : .consumeBundle
    }

    public static let prekeyMinDepth = 20
    public static let prekeyBatch = 100

    public struct Replenish: Sendable, Equatable {
        public var count: Int
        public var startId: Int
    }

    public static func planPrekeyReplenish(remaining: Int, nextId: Int) -> Replenish? {
        if remaining >= prekeyMinDepth { return nil }
        if nextId < 1 { return nil }
        return Replenish(count: prekeyBatch, startId: nextId)
    }

    public enum AuthFailure: String, Sendable {
        case wipe
    }

    public static func onRefreshRejected() -> AuthFailure { .wipe }

    public static let signedPrekeyMaxAgeMs: Int64 = 7 * 24 * 60 * 60 * 1000

    public struct SignedPrekeyPlan: Sendable, Equatable {
        public var nextId: Int
    }

    public static func planSignedPrekeyRotation(currentId: Int, createdAtMs: Int64?, now: Int64) -> SignedPrekeyPlan? {
        if currentId < 1 { return nil }
        guard let createdAtMs else { return nil }
        if now - createdAtMs < signedPrekeyMaxAgeMs { return nil }
        return SignedPrekeyPlan(nextId: currentId + 1)
    }
}

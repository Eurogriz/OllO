import CryptoKit
import Foundation

/// Canonical membership encoding + apply policy. Must stay in lockstep with
/// `packages/crypto/src/membership.ts` and `packages/shared/src/membership.ts`.
public enum Membership {
    public static let domain = "ollo-membership-v1"

    public struct Member: Sendable, Equatable {
        public var userId: String
        public var role: String

        public init(userId: String, role: String) {
            self.userId = userId
            self.role = role
        }
    }

    public struct Local: Sendable, Equatable {
        public var epoch: Int
        public var hash: String

        public init(epoch: Int, hash: String) {
            self.epoch = epoch
            self.hash = hash
        }
    }

    public enum Decision: String, Sendable {
        case accept
        case confirm
        case unchanged
        case stale
        case drop
        case rejected
    }

    public enum MembershipError: Error {
        case invalidRow
        case empty
        case invalidStatement
    }

    public static func canonicalize(_ members: [Member]) throws -> [Member] {
        let sorted = members.sorted { $0.userId < $1.userId }
        var seen = Set<String>()
        var out: [Member] = []
        for m in sorted {
            if m.userId.isEmpty { throw MembershipError.invalidRow }
            if m.role != "admin" && m.role != "moderator" && m.role != "member" {
                throw MembershipError.invalidRow
            }
            if !seen.insert(m.userId).inserted { throw MembershipError.invalidRow }
            out.append(m)
        }
        if out.isEmpty { throw MembershipError.empty }
        return out
    }

    public static func encode(groupId: String, epoch: Int, members: [Member]) throws -> Data {
        if groupId.isEmpty || epoch < 1 { throw MembershipError.invalidStatement }
        let rows = try canonicalize(members)
        var out = Data(domain.utf8)
        out.append(0)
        out.append(Data(groupId.utf8))
        out.append(0)
        out.append(Data(String(epoch).utf8))
        out.append(0)
        for m in rows {
            out.append(Data(m.userId.utf8))
            out.append(0)
            out.append(Data(m.role.utf8))
            out.append(0)
        }
        return out
    }

    public static func hash(groupId: String, epoch: Int, members: [Member]) throws -> String {
        let body = try encode(groupId: groupId, epoch: epoch, members: members)
        return SHA256.hash(data: body).map { String(format: "%02x", $0) }.joined()
    }

    public static func planDelta(local: [Member], incoming: [Member]) -> (added: [String], removed: [String], roleChanged: [String]) {
        let loc = Dictionary(uniqueKeysWithValues: local.filter { !$0.userId.isEmpty }.map { ($0.userId, $0.role) })
        let inc = Dictionary(uniqueKeysWithValues: incoming.filter { !$0.userId.isEmpty }.map { ($0.userId, $0.role) })
        return (
            inc.keys.filter { loc[$0] == nil }.map { $0 },
            loc.keys.filter { inc[$0] == nil }.map { $0 },
            inc.keys.filter { loc[$0] != nil && loc[$0] != inc[$0] }.map { $0 }
        )
    }

    public static func planRejectedHashes(existing: [String], nextHash: String, max: Int = 32) -> [String] {
        if nextHash.isEmpty { return Array(existing.filter { !$0.isEmpty }.suffix(max)) }
        var out = existing.filter { !$0.isEmpty && $0 != nextHash }
        out.append(nextHash)
        return Array(out.suffix(max))
    }

    public static func planSignerNotice(localUserId: String, localDeviceId: String, signerUserId: String, signerDeviceId: String) -> String {
        if localUserId.isEmpty || localDeviceId.isEmpty || signerUserId.isEmpty || signerDeviceId.isEmpty {
            return "other-admin"
        }
        if signerUserId != localUserId { return "other-admin" }
        return signerDeviceId == localDeviceId ? "self" : "own-other-device"
    }

    public static func planApply(
        local: Local?,
        incomingEpoch: Int,
        incomingHash: String,
        signatureValid: Bool,
        signerRole: String,
        signerUserId: String? = nil,
        localMembers: [Member]? = nil,
        incomingMembers: [Member]? = nil,
        rejectedHashes: [String] = []
    ) -> Decision {
        if !signatureValid { return .drop }
        if signerRole != "admin" { return .drop }
        if incomingEpoch < 1 || incomingHash.isEmpty { return .drop }
        if rejectedHashes.contains(incomingHash) { return .rejected }
        if let localMembers, let signerUserId {
            let prior = localMembers.first { $0.userId == signerUserId }
            if prior == nil || prior?.role != "admin" { return .drop }
        }
        guard let local else { return .accept }
        if incomingEpoch < local.epoch { return .stale }
        if incomingEpoch == local.epoch {
            return incomingHash == local.hash ? .unchanged : .drop
        }
        if let localMembers, let incomingMembers {
            let delta = planDelta(local: localMembers, incoming: incomingMembers)
            if !delta.added.isEmpty || !delta.roleChanged.isEmpty { return .confirm }
        }
        return .accept
    }

    public static func trustedMembers(signedUserIds: [String], serverUserIds: [String]) -> (trusted: [String], extra: [String], missing: [String]) {
        let signed = Set(signedUserIds.filter { !$0.isEmpty })
        let server = Set(serverUserIds.filter { !$0.isEmpty })
        return (
            signed.filter { server.contains($0) },
            server.filter { !signed.contains($0) },
            signed.filter { !server.contains($0) }
        )
    }

    /// Fan-out only to the signed ∩ live intersection. Empty signed roster → nobody.
    public static func planFanoutRecipients(signedUserIds: [String], serverUserIds: [String]) -> [String] {
        if !signedUserIds.contains(where: { !$0.isEmpty }) { return [] }
        return trustedMembers(signedUserIds: signedUserIds, serverUserIds: serverUserIds).trusted
    }
}

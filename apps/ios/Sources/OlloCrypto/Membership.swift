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
        case unchanged
        case stale
        case drop
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

    public static func planApply(
        local: Local?,
        incomingEpoch: Int,
        incomingHash: String,
        signatureValid: Bool,
        signerRole: String
    ) -> Decision {
        if !signatureValid { return .drop }
        if signerRole != "admin" { return .drop }
        if incomingEpoch < 1 || incomingHash.isEmpty { return .drop }
        guard let local else { return .accept }
        if incomingEpoch < local.epoch { return .stale }
        if incomingEpoch == local.epoch {
            return incomingHash == local.hash ? .unchanged : .drop
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
}

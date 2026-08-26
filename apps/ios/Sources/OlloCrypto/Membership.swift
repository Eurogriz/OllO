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
        rejectedHashes: [String] = [],
        localDeviceId: String? = nil,
        signerDeviceId: String? = nil
    ) -> Decision {
        if !signatureValid { return .drop }
        if signerRole != "admin" { return .drop }
        if incomingEpoch < 1 || incomingHash.isEmpty { return .drop }
        if rejectedHashes.contains(incomingHash) { return .rejected }
        if let localMembers, let signerUserId {
            let prior = localMembers.first { $0.userId == signerUserId }
            if prior == nil || prior?.role != "admin" { return .drop }
        }
        guard let local else {
            if let localDeviceId, let signerDeviceId {
                return localDeviceId == signerDeviceId ? .accept : .confirm
            }
            return .accept
        }
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

    public static func parseSenderKeySlot(_ slot: String) -> (groupId: String, userId: String, deviceId: String, epoch: String)? {
        let parts = slot.split(separator: ":", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 4 else { return nil }
        let groupId = parts[0]
        let userId = parts[1]
        let deviceId = parts[2]
        let epoch = parts[3]
        if groupId.isEmpty || userId.isEmpty || deviceId.isEmpty || epoch.isEmpty { return nil }
        return (groupId, userId, deviceId, epoch)
    }

    public static func planSenderKeyPrune(slots: [String], userId: String? = nil, deviceId: String? = nil) -> [String] {
        if (userId == nil || userId?.isEmpty == true) && (deviceId == nil || deviceId?.isEmpty == true) { return [] }
        return slots.filter { slot in
            guard let p = parseSenderKeySlot(slot) else { return false }
            if let userId, !userId.isEmpty, p.userId != userId { return false }
            if let deviceId, !deviceId.isEmpty, p.deviceId != deviceId { return false }
            return true
        }
    }

    public static let maxDroppedDevices = 64

    public static func droppedDeviceKey(userId: String, deviceId: String) -> String {
        if userId.isEmpty || deviceId.isEmpty { return "" }
        return "\(userId):\(deviceId)"
    }

    public static func planDroppedDevices(existing: [String], userId: String, deviceId: String, max: Int = maxDroppedDevices) -> [String] {
        let next = droppedDeviceKey(userId: userId, deviceId: deviceId)
        if next.isEmpty { return Array(existing.filter { !$0.isEmpty }.suffix(max)) }
        var out = existing.filter { !$0.isEmpty && $0 != next }
        out.append(next)
        return Array(out.suffix(max))
    }

    public static func planOwnOtherHoldDevices(
        localUserId: String,
        localDeviceId: String,
        pending: [(signerUserId: String, signerDeviceId: String)]
    ) -> [String] {
        var out: [String] = []
        for p in pending {
            if planSignerNotice(
                localUserId: localUserId,
                localDeviceId: localDeviceId,
                signerUserId: p.signerUserId,
                signerDeviceId: p.signerDeviceId
            ) != "own-other-device" {
                continue
            }
            let key = droppedDeviceKey(userId: p.signerUserId, deviceId: p.signerDeviceId)
            if !key.isEmpty && !out.contains(key) { out.append(key) }
        }
        return out
    }

    public static func planSenderKeyIngest(
        trustedUserIds: [String],
        pendingUserIds: [String],
        senderUserId: String,
        senderDeviceId: String? = nil,
        droppedDevices: [String] = [],
        holdDevices: [String] = []
    ) -> String {
        if senderUserId.isEmpty { return "drop" }
        let deviceKey: String
        if let senderDeviceId, !senderDeviceId.isEmpty {
            deviceKey = droppedDeviceKey(userId: senderUserId, deviceId: senderDeviceId)
        } else {
            deviceKey = ""
        }
        if !deviceKey.isEmpty && droppedDevices.contains(deviceKey) { return "drop" }
        if !deviceKey.isEmpty && holdDevices.contains(deviceKey) { return "hold" }
        if trustedUserIds.contains(senderUserId) { return "accept" }
        if pendingUserIds.contains(senderUserId) { return "hold" }
        return "drop"
    }

    public static func planHeldSenderKeyFlush(held: [(slot: String, userId: String)], trustedUserIds: [String]) -> (install: [String], discard: [String]) {
        let trusted = Set(trustedUserIds.filter { !$0.isEmpty })
        return (
            held.filter { trusted.contains($0.userId) }.map { $0.slot },
            held.filter { !trusted.contains($0.userId) }.map { $0.slot }
        )
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

    public static func planSenderKeyEpochRotate(
        groups: [(groupId: String, role: String, epoch: Int)]
    ) -> [(groupId: String, nextEpoch: Int)] {
        var out: [(groupId: String, nextEpoch: Int)] = []
        for g in groups {
            if g.groupId.isEmpty || g.role != "admin" || g.epoch < 1 { continue }
            out.append((groupId: g.groupId, nextEpoch: g.epoch + 1))
        }
        return out
    }

    /// Fan-out only to the signed ∩ live intersection. Empty signed roster → nobody.
    public static func planFanoutRecipients(signedUserIds: [String], serverUserIds: [String]) -> [String] {
        if !signedUserIds.contains(where: { !$0.isEmpty }) { return [] }
        return trustedMembers(signedUserIds: signedUserIds, serverUserIds: serverUserIds).trusted
    }
}

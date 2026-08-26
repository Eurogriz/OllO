package app.ollo.crypto

import java.io.ByteArrayOutputStream
import java.security.MessageDigest

/**
 * Canonical membership encoding + apply policy. Must stay in lockstep with
 * `packages/crypto/src/membership.ts` and `packages/shared/src/membership.ts`.
 * Native sign/verify uses platform Ed25519 later; the hash is SHA-256.
 */
object Membership {
    const val DOMAIN = "ollo-membership-v1"

    data class Member(val userId: String, val role: String)

    data class Local(val epoch: Int, val hash: String)

    enum class Decision { Accept, Confirm, Unchanged, Stale, Drop, Rejected }

    fun canonicalize(members: List<Member>): List<Member> {
        val sorted = members.sortedBy { it.userId }
        val seen = HashSet<String>()
        val out = ArrayList<Member>()
        for (m in sorted) {
            if (m.userId.isEmpty()) throw IllegalArgumentException("invalid membership row")
            if (m.role != "admin" && m.role != "moderator" && m.role != "member") {
                throw IllegalArgumentException("invalid membership row")
            }
            if (!seen.add(m.userId)) throw IllegalArgumentException("duplicate membership row")
            out.add(m)
        }
        if (out.isEmpty()) throw IllegalArgumentException("empty membership")
        return out
    }

    fun encode(groupId: String, epoch: Int, members: List<Member>): ByteArray {
        if (groupId.isEmpty() || epoch < 1) throw IllegalArgumentException("invalid membership statement")
        val rows = canonicalize(members)
        val out = ByteArrayOutputStream()
        out.write(DOMAIN.toByteArray(Charsets.UTF_8))
        out.write(0)
        out.write(groupId.toByteArray(Charsets.UTF_8))
        out.write(0)
        out.write(epoch.toString().toByteArray(Charsets.UTF_8))
        out.write(0)
        for (m in rows) {
            out.write(m.userId.toByteArray(Charsets.UTF_8))
            out.write(0)
            out.write(m.role.toByteArray(Charsets.UTF_8))
            out.write(0)
        }
        return out.toByteArray()
    }

    fun hash(groupId: String, epoch: Int, members: List<Member>): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(encode(groupId, epoch, members))
        return digest.joinToString("") { b -> "%02x".format(b.toInt() and 0xff) }
    }

    fun planDelta(
        local: List<Member>,
        incoming: List<Member>,
    ): Triple<List<String>, List<String>, List<String>> {
        val loc = local.filter { it.userId.isNotEmpty() }.associate { it.userId to it.role }
        val inc = incoming.filter { it.userId.isNotEmpty() }.associate { it.userId to it.role }
        val added = inc.keys.filter { it !in loc }
        val removed = loc.keys.filter { it !in inc }
        val roleChanged = inc.keys.filter { it in loc && loc[it] != inc[it] }
        return Triple(added, removed, roleChanged)
    }

    fun planRejectedHashes(existing: List<String>, nextHash: String, max: Int = 32): List<String> {
        if (nextHash.isEmpty()) return existing.filter { it.isNotEmpty() }.takeLast(max)
        val out = existing.filter { it.isNotEmpty() && it != nextHash }.toMutableList()
        out.add(nextHash)
        return out.takeLast(max)
    }

    fun planSignerNotice(localUserId: String, localDeviceId: String, signerUserId: String, signerDeviceId: String): String {
        if (localUserId.isEmpty() || localDeviceId.isEmpty() || signerUserId.isEmpty() || signerDeviceId.isEmpty()) {
            return "other-admin"
        }
        if (signerUserId != localUserId) return "other-admin"
        return if (signerDeviceId == localDeviceId) "self" else "own-other-device"
    }

    fun planApply(
        local: Local?,
        incomingEpoch: Int,
        incomingHash: String,
        signatureValid: Boolean,
        signerRole: String,
        signerUserId: String? = null,
        localMembers: List<Member>? = null,
        incomingMembers: List<Member>? = null,
        rejectedHashes: Collection<String> = emptyList(),
        localDeviceId: String? = null,
        signerDeviceId: String? = null,
    ): Decision {
        if (!signatureValid) return Decision.Drop
        if (signerRole != "admin") return Decision.Drop
        if (incomingEpoch < 1 || incomingHash.isEmpty()) return Decision.Drop
        if (incomingHash in rejectedHashes) return Decision.Rejected
        if (localMembers != null && signerUserId != null) {
            val prior = localMembers.find { it.userId == signerUserId }
            if (prior == null || prior.role != "admin") return Decision.Drop
        }
        if (local == null) {
            if (localDeviceId != null && signerDeviceId != null) {
                return if (localDeviceId == signerDeviceId) Decision.Accept else Decision.Confirm
            }
            return Decision.Accept
        }
        if (incomingEpoch < local.epoch) return Decision.Stale
        if (incomingEpoch == local.epoch) {
            return if (incomingHash == local.hash) Decision.Unchanged else Decision.Drop
        }
        if (localMembers != null && incomingMembers != null) {
            val (added, _, roleChanged) = planDelta(localMembers, incomingMembers)
            if (added.isNotEmpty() || roleChanged.isNotEmpty()) return Decision.Confirm
        }
        return Decision.Accept
    }

    fun planSenderKeyIngest(trustedUserIds: List<String>, pendingUserIds: List<String>, senderUserId: String): String {
        if (senderUserId.isEmpty()) return "drop"
        if (senderUserId in trustedUserIds) return "accept"
        if (senderUserId in pendingUserIds) return "hold"
        return "drop"
    }

    fun planHeldSenderKeyFlush(held: List<Pair<String, String>>, trustedUserIds: List<String>): Pair<List<String>, List<String>> {
        val trusted = trustedUserIds.filter { it.isNotEmpty() }.toSet()
        val install = held.filter { it.second in trusted }.map { it.first }
        val discard = held.filter { it.second !in trusted }.map { it.first }
        return Pair(install, discard)
    }

    fun trustedMembers(signedUserIds: List<String>, serverUserIds: List<String>): Triple<List<String>, List<String>, List<String>> {
        val signed = signedUserIds.filter { it.isNotEmpty() }.toSet()
        val server = serverUserIds.filter { it.isNotEmpty() }.toSet()
        val trusted = signed.filter { it in server }
        val extra = server.filter { it !in signed }
        val missing = signed.filter { it !in server }
        return Triple(trusted, extra, missing)
    }

    /** Fan-out only to the signed ∩ live intersection. Empty signed roster → nobody. */
    fun planFanoutRecipients(signedUserIds: List<String>, serverUserIds: List<String>): List<String> {
        if (signedUserIds.none { it.isNotEmpty() }) return emptyList()
        return trustedMembers(signedUserIds, serverUserIds).first
    }
}

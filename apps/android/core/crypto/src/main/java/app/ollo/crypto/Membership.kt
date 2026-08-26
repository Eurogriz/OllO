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

    enum class Decision { Accept, Unchanged, Stale, Drop }

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

    fun planApply(
        local: Local?,
        incomingEpoch: Int,
        incomingHash: String,
        signatureValid: Boolean,
        signerRole: String,
    ): Decision {
        if (!signatureValid) return Decision.Drop
        if (signerRole != "admin") return Decision.Drop
        if (incomingEpoch < 1 || incomingHash.isEmpty()) return Decision.Drop
        if (local == null) return Decision.Accept
        if (incomingEpoch < local.epoch) return Decision.Stale
        if (incomingEpoch == local.epoch) {
            return if (incomingHash == local.hash) Decision.Unchanged else Decision.Drop
        }
        return Decision.Accept
    }

    fun trustedMembers(signedUserIds: List<String>, serverUserIds: List<String>): Triple<List<String>, List<String>, List<String>> {
        val signed = signedUserIds.filter { it.isNotEmpty() }.toSet()
        val server = serverUserIds.filter { it.isNotEmpty() }.toSet()
        val trusted = signed.filter { it in server }
        val extra = server.filter { it !in signed }
        val missing = signed.filter { it !in server }
        return Triple(trusted, extra, missing)
    }
}

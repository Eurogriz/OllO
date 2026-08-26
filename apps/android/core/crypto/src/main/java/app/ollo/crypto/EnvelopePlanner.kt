package app.ollo.crypto

/**
 * Offline-first outbound planner. Must stay in lockstep with
 * `packages/shared/src/outbox.ts`. Native production encrypt still uses
 * libsignal; this only decides *whether* to consume a one-time prekey.
 */
object EnvelopePlanner {
    const val MAX_ATTEMPTS = 8
    const val BASE_DELAY_MS = 1500L

    enum class Status {
        Draft,
        Pending,
        Encrypted,
        Uploading,
        Sent,
        Delivered,
        Read,
        Failed,
        Retrying,
    }

    enum class KeyPlan {
        SkipSelf,
        UseSession,
        ConsumeBundle,
    }

    data class OutboxItem(
        val id: String,
        val status: Status,
        val attempts: Int,
    )

    fun nextRetryDelayMs(attempts: Int): Long {
        val exp = attempts.coerceIn(0, 6)
        return BASE_DELAY_MS * (1L shl exp)
    }

    fun onSendFailure(item: OutboxItem): OutboxItem {
        val attempts = item.attempts + 1
        return if (attempts >= MAX_ATTEMPTS) {
            item.copy(attempts = attempts, status = Status.Failed)
        } else {
            item.copy(attempts = attempts, status = Status.Retrying)
        }
    }

    /**
     * Never consume a one-time prekey when a Double Ratchet session exists.
     * Never address the sending device.
     */
    fun planKeyFetch(
        localUserId: String,
        localDeviceId: String,
        targetUserId: String,
        targetDeviceId: String,
        hasSession: Boolean,
    ): KeyPlan {
        if (localUserId == targetUserId && localDeviceId == targetDeviceId) {
            return KeyPlan.SkipSelf
        }
        return if (hasSession) KeyPlan.UseSession else KeyPlan.ConsumeBundle
    }

    const val PREKEY_MIN_DEPTH = 20
    const val PREKEY_BATCH = 100

    data class Replenish(val count: Int, val startId: Int)

    fun planPrekeyReplenish(remaining: Int, nextId: Int): Replenish? {
        if (remaining >= PREKEY_MIN_DEPTH) return null
        if (nextId < 1) return null
        return Replenish(count = PREKEY_BATCH, startId = nextId)
    }

    fun onRefreshRejected(): AuthFailure = AuthFailure.Wipe

    fun afterUnauthorized(refreshSucceeded: Boolean): AuthFailure =
        if (refreshSucceeded) AuthFailure.Retry else AuthFailure.Wipe

    enum class AuthFailure { Wipe, Retry }

    enum class SessionLaunch { SignedIn, NeedAuth }

    /** A wrapped vault session skips OTP. Missing secrets require a bound engine. */
    fun planSessionLaunch(hasVaultSession: Boolean): SessionLaunch =
        if (hasVaultSession) SessionLaunch.SignedIn else SessionLaunch.NeedAuth

    const val SIGNED_PREKEY_MAX_AGE_MS = 7L * 24 * 60 * 60 * 1000
    const val SIGNED_PREKEY_KEEP = 2

    fun keepSignedPrekeyIds(currentId: Int, storedIds: List<Int>): List<Int> {
        val retired = storedIds.filter { it != currentId && it > 0 }.sortedDescending()
        val keep = linkedSetOf<Int>()
        if (currentId > 0) keep.add(currentId)
        keep.addAll(retired.take(SIGNED_PREKEY_KEEP))
        return keep.toList()
    }

    data class SignedPrekeyPlan(val nextId: Int)

    fun planRosterPrune(sessionKeys: List<String>, userId: String, liveDeviceIds: Collection<String>): List<String> {
        if (userId.isEmpty()) return emptyList()
        val live = liveDeviceIds.toSet()
        val prefix = "$userId:"
        return sessionKeys.filter { it.startsWith(prefix) && it.removePrefix(prefix) !in live }
    }

    fun planDeviceDrop(sessionKeys: List<String>, userId: String, deviceId: String): List<String> {
        if (userId.isEmpty() || deviceId.isEmpty()) return emptyList()
        val target = "$userId:$deviceId"
        return sessionKeys.filter { it == target }
    }

    fun planSignedPrekeyRotation(currentId: Int, createdAtMs: Long?, now: Long): SignedPrekeyPlan? {
        if (currentId < 1) return null
        if (createdAtMs == null) return null
        if (now - createdAtMs < SIGNED_PREKEY_MAX_AGE_MS) return null
        return SignedPrekeyPlan(nextId = currentId + 1)
    }

    const val REPLAY_CACHE_MAX = 4096

    enum class ReplayDecision { Accept, Drop }

    /** Bounded FIFO of seen envelope ids. Duplicates must not re-apply. */
    fun rememberEnvelope(ids: MutableList<String>, envelopeId: String, max: Int = REPLAY_CACHE_MAX): ReplayDecision {
        if (envelopeId.isEmpty() || max < 1) return ReplayDecision.Drop
        if (ids.contains(envelopeId)) return ReplayDecision.Drop
        ids.add(envelopeId)
        while (ids.size > max) ids.removeAt(0)
        return ReplayDecision.Accept
    }
}

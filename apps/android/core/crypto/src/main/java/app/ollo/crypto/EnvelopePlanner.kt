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

    fun planSignedPrekeyRotation(currentId: Int, createdAtMs: Long?, now: Long): SignedPrekeyPlan? {
        if (currentId < 1) return null
        if (createdAtMs == null) return null
        if (now - createdAtMs < SIGNED_PREKEY_MAX_AGE_MS) return null
        return SignedPrekeyPlan(nextId = currentId + 1)
    }
}

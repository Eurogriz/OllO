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
}

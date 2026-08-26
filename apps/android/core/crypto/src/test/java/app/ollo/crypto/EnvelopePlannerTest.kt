package app.ollo.crypto

import org.junit.Assert.assertEquals
import org.junit.Test

class EnvelopePlannerTest {
    @Test
    fun retriesThenFailsClosed() {
        var item = EnvelopePlanner.OutboxItem(id = "m1", status = EnvelopePlanner.Status.Pending, attempts = 0)
        repeat(EnvelopePlanner.MAX_ATTEMPTS - 1) {
            item = EnvelopePlanner.onSendFailure(item)
            assertEquals(EnvelopePlanner.Status.Retrying, item.status)
        }
        item = EnvelopePlanner.onSendFailure(item)
        assertEquals(EnvelopePlanner.Status.Failed, item.status)
        assertEquals(EnvelopePlanner.MAX_ATTEMPTS, item.attempts)
        assertEquals(1500L, EnvelopePlanner.nextRetryDelayMs(0))
        assertEquals(12000L, EnvelopePlanner.nextRetryDelayMs(3))
    }

    @Test
    fun skipsSelfAndDoesNotBurnOpkWhenSessionExists() {
        assertEquals(
            EnvelopePlanner.KeyPlan.SkipSelf,
            EnvelopePlanner.planKeyFetch("u1", "d1", "u1", "d1", hasSession = false),
        )
        assertEquals(
            EnvelopePlanner.KeyPlan.UseSession,
            EnvelopePlanner.planKeyFetch("u1", "d1", "u2", "d9", hasSession = true),
        )
        assertEquals(
            EnvelopePlanner.KeyPlan.ConsumeBundle,
            EnvelopePlanner.planKeyFetch("u1", "d1", "u2", "d9", hasSession = false),
        )
    }

    @Test
    fun rotatesSignedPrekeyOnlyAfterMaxAge() {
        val now = 1_700_000_000_000L
        assertEquals(null, EnvelopePlanner.planSignedPrekeyRotation(1, now, now))
        assertEquals(null, EnvelopePlanner.planSignedPrekeyRotation(1, null, now))
        assertEquals(null, EnvelopePlanner.planSignedPrekeyRotation(0, 1L, now))
        assertEquals(
            EnvelopePlanner.SignedPrekeyPlan(2),
            EnvelopePlanner.planSignedPrekeyRotation(1, now - EnvelopePlanner.SIGNED_PREKEY_MAX_AGE_MS, now),
        )
        assertEquals(listOf(5, 4, 3), EnvelopePlanner.keepSignedPrekeyIds(5, listOf(1, 2, 3, 4, 5)))
        assertEquals(EnvelopePlanner.AuthFailure.Retry, EnvelopePlanner.afterUnauthorized(true))
        assertEquals(EnvelopePlanner.AuthFailure.Wipe, EnvelopePlanner.afterUnauthorized(false))
        assertEquals(
            listOf("u1:d2"),
            EnvelopePlanner.planRosterPrune(listOf("u1:d1", "u1:d2", "u10:d1"), "u1", listOf("d1")),
        )
        assertEquals(listOf("u1:d2"), EnvelopePlanner.planDeviceDrop(listOf("u1:d1", "u1:d2"), "u1", "d2"))
    }

    @Test
    fun unboundEngineDoesNotInventIdentity() {
        try {
            DevicePayload.requireIdentity(UnboundCryptoEngine())
            throw AssertionError("expected unbound engine to fail closed")
        } catch (e: IllegalStateException) {
            assertEquals("libsignal engine is not bound", e.message)
        }
    }
}

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
}

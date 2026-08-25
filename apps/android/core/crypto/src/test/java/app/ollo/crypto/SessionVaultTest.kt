package app.ollo.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SessionVaultTest {
    private val wrap = ByteArray(32) { 5 }

    @Test
    fun sealsTokensAndWipesOnRefreshReject() {
        val store = IdentityStore()
        val proto = ProtocolStore(store, wrap)
        proto.sessionVault.save(SessionSecrets("u1", "d1", "access-secret", "refresh-secret"))
        val loaded = proto.sessionVault.load()!!
        assertEquals("u1", loaded.userId)
        assertEquals("refresh-secret", loaded.refresh)
        assertEquals(EnvelopePlanner.AuthFailure.Wipe, EnvelopePlanner.onRefreshRejected())
        proto.wipe()
        assertNull(SessionVault(store, wrap).load())
        assertTrue(store.isEmpty())
    }

    @Test
    fun rosterHashChangesWhenACloneDeviceAppears() {
        val ik = ByteArray(32) { 1 }
        val one = DeviceRoster.hash(listOf(DeviceRoster.Device("d1", ik)))
        val two = DeviceRoster.hash(
            listOf(DeviceRoster.Device("d2", ik), DeviceRoster.Device("d1", ik)),
        )
        assertTrue(one != two)
        assertEquals(DeviceRoster.Decision.Changed, DeviceRoster.note(one, two))
        assertEquals(DeviceRoster.Decision.Unchanged, DeviceRoster.note(two, two))
    }

    @Test
    fun replenishOnlyWhenDepthIsLow() {
        assertNull(EnvelopePlanner.planPrekeyReplenish(20, 11))
        val plan = EnvelopePlanner.planPrekeyReplenish(19, 11)!!
        assertEquals(100, plan.count)
        assertEquals(11, plan.startId)
    }
}

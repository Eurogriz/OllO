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

    @Test
    fun controllerRotatesTokensAndWipesOnFailedRefresh() {
        val store = IdentityStore()
        val proto = ProtocolStore(store, wrap, "u1", "d1")
        proto.sessions.saveSession(SessionDirectory.Address("u2", "d9"), byteArrayOf(1, 2, 3))
        val ctl = SessionController(proto)
        ctl.save(SessionSecrets("u1", "d1", "access-1", "refresh-1"))
        assertEquals("access-1", ctl.restore()!!.access)
        assertTrue(ctl.applyRefresh("access-2", "refresh-2"))
        assertEquals("refresh-2", proto.sessionVault.load()!!.refresh)
        assertEquals(EnvelopePlanner.AuthFailure.Retry, ctl.onUnauthorized(true))
        assertEquals("access-2", ctl.access())
        assertEquals(EnvelopePlanner.AuthFailure.Wipe, ctl.onUnauthorized(false))
        assertNull(ctl.access())
        assertNull(proto.sessionVault.load())
        assertNull(proto.sessions.loadSession(SessionDirectory.Address("u2", "d9")))
        assertTrue(store.isEmpty())
    }
}

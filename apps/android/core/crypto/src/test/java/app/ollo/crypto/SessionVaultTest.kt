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
    fun refusesAnUnsignedExtraGroupMember() {
        val members = listOf(
            Membership.Member("b", "member"),
            Membership.Member("a", "admin"),
        )
        val h1 = Membership.hash("g1", 1, members)
        val h2 = Membership.hash("g1", 1, members.reversed())
        assertEquals(h1, h2)
        assertEquals(
            Membership.Decision.Drop,
            Membership.planApply(null, 1, h1, false, "admin"),
        )
        val (trusted, extra, _) = Membership.trustedMembers(listOf("a", "b"), listOf("a", "b", "eve"))
        assertEquals(listOf("a", "b"), trusted)
        assertEquals(listOf("eve"), extra)
    }

    @Test
    fun dropsAReplayedEnvelopeAndClearsOnWipe() {
        val store = IdentityStore()
        val proto = ProtocolStore(store, wrap)
        assertEquals(EnvelopePlanner.ReplayDecision.Accept, proto.rememberEnvelope("e1"))
        assertEquals(EnvelopePlanner.ReplayDecision.Drop, proto.rememberEnvelope("e1"))
        assertEquals(EnvelopePlanner.ReplayDecision.Accept, proto.rememberEnvelope("e2"))
        val ids = arrayListOf("a", "b")
        assertEquals(EnvelopePlanner.ReplayDecision.Accept, EnvelopePlanner.rememberEnvelope(ids, "c", 2))
        assertEquals(listOf("b", "c"), ids)
        proto.wipe()
        assertEquals(EnvelopePlanner.ReplayDecision.Accept, ProtocolStore(store, wrap).rememberEnvelope("e1"))
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

    @Test
    fun launchFollowsVaultThenWipe() {
        val proto = ProtocolStore(IdentityStore(), wrap)
        val ctl = SessionController(proto)
        assertEquals(EnvelopePlanner.SessionLaunch.NeedAuth, ctl.launch())
        ctl.save(SessionSecrets("u1", "d1", "access-1", "refresh-1"))
        assertEquals(EnvelopePlanner.SessionLaunch.SignedIn, ctl.launch())
        ctl.wipe()
        assertEquals(EnvelopePlanner.SessionLaunch.NeedAuth, ctl.launch())
        assertNull(ctl.restore())
    }
}

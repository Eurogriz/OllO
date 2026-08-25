package app.ollo.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SessionDirectoryTest {
    private val wrap = ByteArray(32) { 9 }

    @Test
    fun blobMapKnownAnswer() {
        val encoded = BlobMap.encode(linkedMapOf("a" to byteArrayOf(0xFF.toByte())))
        val expected = byteArrayOf(
            0x4F, 0x4C, 0x4D, 0x31,
            0x00, 0x00, 0x00, 0x01,
            0x00, 0x01, 0x61,
            0x00, 0x00, 0x00, 0x01, 0xFF.toByte(),
        )
        assertArrayEquals(expected, encoded)
        val back = BlobMap.decode(encoded)
        assertArrayEquals(byteArrayOf(0xFF.toByte()), back["a"])
    }

    @Test
    fun persistsOpaqueSessionAndPlansFetch() {
        val dir = SessionDirectory(IdentityStore(), wrap, localUserId = "u1", localDeviceId = "d1")
        val peer = SessionDirectory.Address("u2", "d9")
        assertEquals(EnvelopePlanner.KeyPlan.ConsumeBundle, dir.planFetch("u2", "d9"))
        dir.saveSession(peer, byteArrayOf(1, 2, 3, 4))
        assertTrue(dir.hasSession(peer))
        assertArrayEquals(byteArrayOf(1, 2, 3, 4), dir.loadSession(peer))
        assertEquals(EnvelopePlanner.KeyPlan.UseSession, dir.planFetch("u2", "d9"))
        assertEquals(EnvelopePlanner.KeyPlan.SkipSelf, dir.planFetch("u1", "d1"))
    }

    @Test
    fun identityChangeDoesNotOverwrite() {
        val dir = SessionDirectory(IdentityStore(), wrap)
        val addr = SessionDirectory.Address("u2", "d9")
        val first = ByteArray(32) { 1 }
        val second = ByteArray(32) { 2 }
        assertEquals(SessionDirectory.IdentityDecision.New, dir.noteRemoteIdentity(addr, first))
        assertEquals(SessionDirectory.IdentityDecision.Unchanged, dir.noteRemoteIdentity(addr, first))
        assertEquals(SessionDirectory.IdentityDecision.Changed, dir.noteRemoteIdentity(addr, second))
        assertEquals(SessionDirectory.IdentityDecision.Unchanged, dir.noteRemoteIdentity(addr, first))
        dir.replaceRemoteIdentity(addr, second)
        assertEquals(SessionDirectory.IdentityDecision.Unchanged, dir.noteRemoteIdentity(addr, second))
    }

    @Test
    fun wipeDropsSessionsAndIdentities() {
        val store = IdentityStore()
        val dir = SessionDirectory(store, wrap, localUserId = "u1", localDeviceId = "d1")
        dir.saveSession(SessionDirectory.Address("u2", "d9"), byteArrayOf(7))
        dir.noteRemoteIdentity(SessionDirectory.Address("u2", "d9"), ByteArray(32) { 3 })
        dir.wipe()
        assertTrue(store.isEmpty())
        val again = SessionDirectory(store, wrap, localUserId = "u1", localDeviceId = "d1")
        assertFalse(again.hasSession(SessionDirectory.Address("u2", "d9")))
        assertNull(again.loadSession(SessionDirectory.Address("u2", "d9")))
        assertEquals(EnvelopePlanner.KeyPlan.ConsumeBundle, again.planFetch("u2", "d9"))
    }

    @Test
    fun unboundEngineFailsClosed() {
        val engine = UnboundCryptoEngine()
        try {
            engine.encrypt(SessionHandle("x"), byteArrayOf(1))
            throw AssertionError("expected unbound engine to throw")
        } catch (e: IllegalStateException) {
            assertTrue(e.message!!.contains("libsignal"))
        }
        val digits = engine.safetyNumber(ByteArray(32) { 1 }, ByteArray(32) { 2 })
        assertEquals(60, digits.length)
    }
}

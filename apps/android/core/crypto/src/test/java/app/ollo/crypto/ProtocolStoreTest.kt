package app.ollo.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class ProtocolStoreTest {
    private val wrap = ByteArray(32) { 11 }

    @Test
    fun durableDirectorySurvivesRestart() {
        val dir = File(System.getProperty("java.io.tmpdir"), "ollo-proto-${System.nanoTime()}")
        try {
            val first = ProtocolStore(IdentityStore(directory = dir), wrap, "u1", "d1")
            first.storeLocalIdentity(byteArrayOf(9, 8, 7), registrationId = 42)
            first.storePreKey(3, byteArrayOf(1, 1, 1))
            first.storeSignedPreKey(1, byteArrayOf(2, 2))
            first.sessions.saveSession(SessionDirectory.Address("u2", "d9"), byteArrayOf(4, 5, 6))
            first.messages.put(
                LocalMessage("c1", "t1", "u2", 1000L, "sent", byteArrayOf(65), expiresAt = null),
            )
            val idx = ThreadIndex()
            idx.upsert(ChatThread(id = "t1", title = "bob", peerUserId = "u2"))
            first.saveThreads(idx)

            val again = ProtocolStore(IdentityStore(directory = dir), wrap, "u1", "d1")
            assertArrayEquals(byteArrayOf(9, 8, 7), again.loadLocalIdentity())
            assertEquals(42, again.registrationId())
            assertArrayEquals(byteArrayOf(1, 1, 1), again.loadPreKey(3))
            assertArrayEquals(byteArrayOf(2, 2), again.loadSignedPreKey(1))
            assertArrayEquals(byteArrayOf(4, 5, 6), again.sessions.loadSession(SessionDirectory.Address("u2", "d9")))
            assertEquals(EnvelopePlanner.KeyPlan.UseSession, again.planFetch("u2", "d9"))
            assertEquals("bob", again.loadThreads().visible().single().title)
            assertEquals("c1", again.messages.list("t1").single().clientId)
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun consumePrekeyAndIdentityChangeStayFailClosed() {
        val proto = ProtocolStore(IdentityStore(), wrap, "u1", "d1")
        proto.storePreKey(7, byteArrayOf(9))
        proto.removePreKey(7)
        assertNull(proto.loadPreKey(7))
        val addr = SessionDirectory.Address("u2", "d9")
        assertEquals(SessionDirectory.IdentityDecision.New, proto.sessions.noteRemoteIdentity(addr, ByteArray(32) { 1 }))
        assertEquals(SessionDirectory.IdentityDecision.Changed, proto.sessions.noteRemoteIdentity(addr, ByteArray(32) { 2 }))
        assertEquals(SessionDirectory.IdentityDecision.Unchanged, proto.sessions.noteRemoteIdentity(addr, ByteArray(32) { 1 }))
    }

    @Test
    fun messageTtlExpiresAndWipeDeletesFiles() {
        val dir = File(System.getProperty("java.io.tmpdir"), "ollo-hist-${System.nanoTime()}")
        try {
            val proto = ProtocolStore(IdentityStore(directory = dir), wrap)
            proto.messages.put(LocalMessage("live", "t1", "u1", 1L, "sent", byteArrayOf(1), expiresAt = 9_000L))
            proto.messages.put(LocalMessage("dead", "t1", "u1", 2L, "sent", byteArrayOf(2), expiresAt = 1_000L))
            assertEquals(1, proto.messages.expire(now = 2_000L))
            assertEquals(listOf("live"), proto.messages.list("t1").map { it.clientId })
            proto.wipe()
            assertTrue(IdentityStore(directory = dir).isEmpty())
            assertTrue(dir.listFiles()?.none { it.isFile && !it.name.endsWith(".tmp") } ?: true)
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun messageCodecKnownAnswer() {
        val msg = LocalMessage("c", "t", "s", 1L, "sent", byteArrayOf(0xAA.toByte()), expiresAt = null)
        val encoded = LocalMessageCodec.encode(msg)
        val expectedHead = byteArrayOf(0x4F, 0x4C, 0x4D, 0x32, 0x00, 0x01, 0x63)
        assertArrayEquals(expectedHead, encoded.copyOfRange(0, expectedHead.size))
        val back = LocalMessageCodec.decode(encoded)
        assertEquals("c", back.clientId)
        assertEquals("t", back.threadId)
        assertNull(back.expiresAt)
        assertArrayEquals(byteArrayOf(0xAA.toByte()), back.body)
    }

    @Test
    fun pruneSignedPreKeysKeepsCurrentAndTwoRetired() {
        val proto = ProtocolStore(IdentityStore(), wrap)
        proto.storeSignedPreKey(1, byteArrayOf(1))
        proto.storeSignedPreKey(2, byteArrayOf(2))
        proto.storeSignedPreKey(3, byteArrayOf(3))
        proto.storeSignedPreKey(4, byteArrayOf(4))
        proto.storeSignedPreKey(5, byteArrayOf(5))
        proto.pruneSignedPreKeys(5)
        assertNull(proto.loadSignedPreKey(1))
        assertNull(proto.loadSignedPreKey(2))
        assertArrayEquals(byteArrayOf(3), proto.loadSignedPreKey(3))
        assertArrayEquals(byteArrayOf(4), proto.loadSignedPreKey(4))
        assertArrayEquals(byteArrayOf(5), proto.loadSignedPreKey(5))
    }

    @Test
    fun rejectsPathTraversalKeys() {
        val store = IdentityStore()
        try {
            store.put(wrap, "../etc", byteArrayOf(1))
            throw AssertionError("expected unsafe key to throw")
        } catch (_: IllegalArgumentException) {
        }
    }
}

package app.ollo.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ThreadIndexTest {
    @Test
    fun startsEmptyAndNeverSeedsDemoChats() {
        val index = ThreadIndex()
        assertTrue(index.isEmpty())
        assertTrue(index.visible().isEmpty())
        index.upsert(ChatThread(id = "t1", title = "bob", peerUserId = "u-bob"))
        assertEquals(1, index.visible().size)
        index.archive("t1")
        assertTrue(index.isEmpty())
        index.wipe()
        assertTrue(index.visible().isEmpty())
    }

    @Test
    fun roundTripsIncludingArchived() {
        val index = ThreadIndex()
        index.upsert(ChatThread(id = "t1", title = "bob", preview = "hi", peerUserId = "u-bob", muted = true))
        index.upsert(ChatThread(id = "t2", title = "team", groupId = "g1", archived = true))
        val back = ThreadIndex.decode(index.encode())
        assertEquals("bob", back.visible().single().title)
        assertEquals(true, back.visible().single().muted)
        assertEquals(2, back.snapshot().size)
        assertEquals("g1", back.snapshot().first { it.id == "t2" }.groupId)
    }
}

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
}

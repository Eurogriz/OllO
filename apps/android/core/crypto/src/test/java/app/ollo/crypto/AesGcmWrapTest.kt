package app.ollo.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AesGcmWrapTest {
    @Test
    fun roundTripAndTamperFails() {
        val key = ByteArray(32) { 7 }
        val pt = "x25519-private-must-not-be-plaintext".toByteArray(Charsets.UTF_8)
        val blob = AesGcmWrap.seal(key, pt)
        assertArrayEquals(pt, AesGcmWrap.open(key, blob))
        val other = ByteArray(32) { 8 }
        var failed = false
        try {
            AesGcmWrap.open(other, blob)
        } catch (_: Exception) {
            failed = true
        }
        assertTrue(failed)
        blob[blob.lastIndex] = (blob[blob.lastIndex].toInt() xor 1).toByte()
        failed = false
        try {
            AesGcmWrap.open(key, blob)
        } catch (_: Exception) {
            failed = true
        }
        assertTrue(failed)
    }

    @Test
    fun identityStoreWipeDropsSecrets() {
        val key = ByteArray(32) { 3 }
        val store = IdentityStore()
        store.put(key, IdentityStore.Slot.Identity, byteArrayOf(1, 2, 3))
        store.put(key, IdentityStore.Slot.Sessions, byteArrayOf(4, 5))
        assertEquals(3, store.get(key, IdentityStore.Slot.Identity)?.size)
        val n = store.wipe()
        assertEquals(2, n)
        assertTrue(store.isEmpty())
        assertEquals(null, store.get(key, IdentityStore.Slot.Identity))
    }
}

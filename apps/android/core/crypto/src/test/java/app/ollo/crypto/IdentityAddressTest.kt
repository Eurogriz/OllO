package app.ollo.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class IdentityAddressTest {
    @Test
    fun encodeParseAndAuthProof() {
        val ik = ByteArray(32) { 7 }
        val uri = IdentityAddress.encode(ik)
        assertTrue(uri.startsWith(IdentityAddress.PREFIX))
        assertArrayEquals(ik, IdentityAddress.parse(uri))
        assertArrayEquals(ik, IdentityAddress.parse(uri.removePrefix(IdentityAddress.PREFIX)))
        assertNull(IdentityAddress.parse(""))
        assertNull(IdentityAddress.parse("ollo:user:v1:???"))
        assertEquals("", IdentityAddress.encode(ByteArray(32)))
        val proof = IdentityAddress.authProof("ch_1", "nonce-a")
        val domain = IdentityAddress.AUTH_PROOF_DOMAIN.toByteArray(Charsets.UTF_8)
        assertEquals(IdentityAddress.AUTH_PROOF_DOMAIN, String(proof.copyOfRange(0, domain.size), Charsets.UTF_8))
        assertEquals(0, IdentityAddress.authProof("", "n").size)
    }

    @Test
    fun prefixDjbRejectsWrongLength() {
        try {
            LibsignalEngine.prefixDjb(ByteArray(0))
            throw AssertionError("expected empty key to fail closed")
        } catch (_: IllegalArgumentException) {
        }
        try {
            LibsignalEngine.prefixDjb(ByteArray(31) { 1 })
            throw AssertionError("expected 31-byte key to fail closed")
        } catch (_: IllegalArgumentException) {
        }
        val ok = LibsignalEngine.prefixDjb(ByteArray(32) { 1 })
        assertEquals(33, ok.size)
        assertEquals(LibsignalEngine.DJB_TYPE, ok[0])
        assertArrayEquals(ByteArray(32) { 1 }, LibsignalEngine.stripDjb(ok))
    }
}

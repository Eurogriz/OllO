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
}

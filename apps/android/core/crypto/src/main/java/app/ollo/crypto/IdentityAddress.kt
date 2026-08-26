package app.ollo.crypto

import java.util.Base64

/**
 * Account address is the long-term identity Ed25519 public key, not a phone.
 * Private key never appears in this encoding.
 */
object IdentityAddress {
    const val PREFIX = "ollo:user:v1:"
    const val AUTH_PROOF_DOMAIN = "ollo-auth-v1"

    fun encode(ed25519Public: ByteArray): String {
        if (ed25519Public.size != 32 || ed25519Public.all { it == 0.toByte() }) return ""
        return PREFIX + b64url(ed25519Public)
    }

    fun parse(raw: String): ByteArray? {
        val s = raw.trim()
        if (s.isEmpty()) return null
        val payload = if (s.startsWith(PREFIX)) s.substring(PREFIX.length) else s
        val bytes = b64urlDecode(payload) ?: return null
        if (bytes.size != 32 || bytes.all { it == 0.toByte() }) return null
        return bytes
    }

    /** Canonical bytes signed to prove possession of the identity Ed25519 key. */
    fun authProof(challengeId: String, nonce: String): ByteArray {
        if (challengeId.isEmpty() || nonce.isEmpty()) return ByteArray(0)
        val a = AUTH_PROOF_DOMAIN.toByteArray(Charsets.UTF_8)
        val b = challengeId.toByteArray(Charsets.UTF_8)
        val c = nonce.toByteArray(Charsets.UTF_8)
        return a + byteArrayOf(0) + b + byteArrayOf(0) + c
    }

    private fun b64url(bytes: ByteArray): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

    private fun b64urlDecode(raw: String): ByteArray? {
        return try {
            Base64.getUrlDecoder().decode(raw)
        } catch (_: IllegalArgumentException) {
            null
        }
    }
}

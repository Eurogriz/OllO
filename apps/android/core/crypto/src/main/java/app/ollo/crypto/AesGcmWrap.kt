package app.ollo.crypto

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * AES-256-GCM wrap used for SQLCipher passphrases and identity blobs
 * when the wrapping key is already in hand (tests, or after Keystore unwrap).
 *
 * AAD is `ollo-wrap-v1`. Layout: 12-byte IV || ciphertext || 16-byte tag.
 * Android Keystore uses the same layout and AAD; it never exports the key.
 */
object AesGcmWrap {
    const val AAD = "ollo-wrap-v1"
    private const val IV_LEN = 12
    private const val TAG_BITS = 128

    fun seal(key: ByteArray, plaintext: ByteArray, nonce: ByteArray? = null): ByteArray {
        require(key.size == 32) { "wrap key must be 32 bytes" }
        val iv = nonce ?: ByteArray(IV_LEN).also { SecureRandom().nextBytes(it) }
        require(iv.size == IV_LEN) { "GCM nonce must be 12 bytes" }
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, iv))
        c.updateAAD(AAD.toByteArray(Charsets.UTF_8))
        val ct = c.doFinal(plaintext)
        return iv + ct
    }

    fun open(key: ByteArray, blob: ByteArray): ByteArray {
        require(key.size == 32) { "wrap key must be 32 bytes" }
        require(blob.size > IV_LEN + 16) { "wrap blob too short" }
        val iv = blob.copyOfRange(0, IV_LEN)
        val ct = blob.copyOfRange(IV_LEN, blob.size)
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, iv))
        c.updateAAD(AAD.toByteArray(Charsets.UTF_8))
        return c.doFinal(ct)
    }
}

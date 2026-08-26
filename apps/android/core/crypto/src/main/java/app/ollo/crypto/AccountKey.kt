package app.ollo.crypto

import android.util.Base64
import com.google.crypto.tink.subtle.Ed25519Sign
import com.google.crypto.tink.subtle.Ed25519Verify

/**
 * Long-term **account** identity. Real Ed25519 (Tink), not a libsignal
 * IdentityKeyPair. libsignal identity is XEdDSA and will not verify on the
 * server (`@noble/curves` Ed25519). Mixing the two is a release blocker.
 */
class AccountKey private constructor(
    val privateSeed: ByteArray,
    val publicKey: ByteArray,
) {
    init {
        require(privateSeed.size == 32) { "account private seed must be 32 bytes" }
        require(publicKey.size == 32) { "account public key must be 32 bytes" }
        require(publicKey.any { it != 0.toByte() }) { "account public key is all-zero" }
    }

    fun sign(message: ByteArray): ByteArray = Ed25519Sign(privateSeed).sign(message)

    fun verify(message: ByteArray, signature: ByteArray): Boolean =
        try {
            Ed25519Verify(publicKey).verify(signature, message)
            true
        } catch (_: Throwable) {
            false
        }

    fun publicB64(): String = Base64.encodeToString(publicKey, Base64.NO_WRAP)

    companion object {
        fun generate(): AccountKey {
            val pair = Ed25519Sign.KeyPair.newKeyPair()
            return AccountKey(pair.privateKey.copyOf(), pair.publicKey.copyOf())
        }

        fun fromSeed(privateSeed: ByteArray, publicKey: ByteArray): AccountKey =
            AccountKey(privateSeed.copyOf(), publicKey.copyOf())
    }
}

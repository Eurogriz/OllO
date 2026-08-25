package app.ollo.crypto

/**
 * Client-facing crypto port. Production implementation MUST be libsignal.
 * The TypeScript engine in packages/crypto is a review-required reference
 * for web/tests and is not used on Android release builds.
 */
interface CryptoEngine {
    fun generateIdentity(): IdentityMaterial
    fun processPrekeyBundle(remote: ByteArray): SessionHandle
    fun encrypt(session: SessionHandle, plaintext: ByteArray): ByteArray
    fun decrypt(session: SessionHandle, payload: ByteArray): ByteArray
    fun safetyNumber(localIdentity: ByteArray, remoteIdentity: ByteArray): String
}

data class IdentityMaterial(
    val identityX25519: ByteArray,
    val identityEd25519: ByteArray,
    val signedPrekey: ByteArray,
    val signedPrekeySignature: ByteArray,
    val oneTimePrekeys: List<ByteArray>,
)

class SessionHandle(val id: String)

package app.ollo.crypto

/**
 * Client-facing crypto port. Production implementation MUST be official
 * libsignal (`org.signal:libsignal-client`). Do not implement a homegrown
 * Double Ratchet behind this interface.
 *
 * The TypeScript engine in `packages/crypto` is a review-required reference
 * for web/tests and is not used on Android release builds.
 */
interface CryptoEngine {
    fun generateIdentity(): IdentityMaterial
    fun deviceRegistrationJson(name: String, platform: String): String
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

/**
 * Fails closed until a libsignal-backed engine is bound. Shipping this
 * class as the production engine is a release blocker.
 */
class UnboundCryptoEngine : CryptoEngine {
    override fun generateIdentity(): IdentityMaterial =
        throw IllegalStateException("libsignal engine is not bound")

    override fun deviceRegistrationJson(name: String, platform: String): String =
        throw IllegalStateException("libsignal engine is not bound")

    override fun processPrekeyBundle(remote: ByteArray): SessionHandle =
        throw IllegalStateException("libsignal engine is not bound")

    override fun encrypt(session: SessionHandle, plaintext: ByteArray): ByteArray =
        throw IllegalStateException("libsignal engine is not bound")

    override fun decrypt(session: SessionHandle, payload: ByteArray): ByteArray =
        throw IllegalStateException("libsignal engine is not bound")

    override fun safetyNumber(localIdentity: ByteArray, remoteIdentity: ByteArray): String =
        SafetyNumber.of(localIdentity, remoteIdentity).digits
}

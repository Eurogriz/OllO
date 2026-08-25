package app.ollo.crypto

/**
 * Registration identity is produced only by a bound [CryptoEngine].
 * [UnboundCryptoEngine] throws; the UI must not invent keys or skip OTP.
 */
object DevicePayload {
    fun requireIdentity(engine: CryptoEngine): IdentityMaterial = engine.generateIdentity()
}

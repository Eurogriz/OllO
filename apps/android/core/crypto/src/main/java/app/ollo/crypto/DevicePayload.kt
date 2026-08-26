package app.ollo.crypto

/**
 * Registration identity is produced only by a bound [CryptoEngine].
 * [UnboundCryptoEngine] throws; the UI must not invent keys, registration
 * ids, or skip OTP.
 */
object DevicePayload {
    fun requireIdentity(engine: CryptoEngine): IdentityMaterial = engine.generateIdentity()

    fun requireRegistration(engine: CryptoEngine, name: String, platform: String): String =
        engine.deviceRegistrationJson(name, platform)
}

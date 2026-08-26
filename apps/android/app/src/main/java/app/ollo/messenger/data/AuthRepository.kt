package app.ollo.messenger.data

import app.ollo.crypto.CryptoEngine
import app.ollo.crypto.IdentityAddress
import app.ollo.crypto.SessionController
import app.ollo.crypto.SessionSecrets
import app.ollo.network.OlloApi
import org.json.JSONObject
import java.util.Base64

class AuthRepository(
    private val api: OlloApi,
    private val sessions: SessionController? = null,
) {
    fun requestOtp(phone: String): Pair<String, String?> {
        val raw = api.requestOtp(phone)
        val json = JSONObject(raw)
        val dev = if (json.has("dev_otp") && !json.isNull("dev_otp")) json.getString("dev_otp") else null
        return json.getString("challenge_id") to dev
    }

    fun challenge(): Pair<String, String> {
        val json = JSONObject(api.authChallenge())
        return json.getString("challenge_id") to json.getString("nonce")
    }

    fun registerKey(
        challengeId: String,
        accountEd25519B64: String,
        signatureB64: String,
        deviceJson: String,
        registrationLock: String? = null,
    ): Session {
        require(accountEd25519B64.isNotEmpty()) { "account key required" }
        val device = JSONObject(deviceJson)
        require(device.has("identity_key_x25519") && device.has("identity_key_ed25519")) {
            "libsignal engine is not bound"
        }
        require(device.has("registration_id") && device.has("signed_prekey") && device.has("one_time_prekeys")) {
            "libsignal engine is not bound"
        }
        val body = JSONObject()
            .put("challenge_id", challengeId)
            .put("account_ed25519", accountEd25519B64)
            .put("signature", signatureB64)
            .put("device", device)
        if (!registrationLock.isNullOrEmpty()) body.put("registration_lock", registrationLock)
        val raw = api.post("/v1/auth/register-key", body.toString(), auth = false)
        return persistSession(raw)
    }

    fun signInWithKey(
        engine: CryptoEngine,
        account: app.ollo.crypto.AccountKey,
        name: String,
        platform: String,
        registrationLock: String? = null,
    ): Session {
        val deviceJson = engine.deviceRegistrationJson(name, platform)
        val (challengeId, nonce) = challenge()
        val proof = IdentityAddress.authProof(challengeId, nonce)
        val signature = Base64.getEncoder().encodeToString(account.sign(proof))
        return registerKey(challengeId, account.publicB64(), signature, deviceJson, registrationLock)
    }

    fun verify(
        challengeId: String,
        otp: String,
        accountEd25519B64: String,
        deviceJson: String,
        registrationLock: String? = null,
    ): Session {
        require(accountEd25519B64.isNotEmpty()) { "account key required" }
        val device = JSONObject(deviceJson)
        require(device.has("identity_key_x25519") && device.has("identity_key_ed25519")) {
            "libsignal engine is not bound"
        }
        require(device.has("registration_id") && device.has("signed_prekey") && device.has("one_time_prekeys")) {
            "libsignal engine is not bound"
        }
        val body = JSONObject()
            .put("challenge_id", challengeId)
            .put("otp", otp)
            .put("account_ed25519", accountEd25519B64)
            .put("device", device)
        if (!registrationLock.isNullOrEmpty()) body.put("registration_lock", registrationLock)
        val raw = api.post("/v1/auth/verify-otp", body.toString(), auth = false)
        return persistSession(raw)
    }

    private fun persistSession(raw: String): Session {
        val json = JSONObject(raw)
        val user = json.getJSONObject("user")
        val session = Session(
            userId = user.getString("id"),
            username = if (user.isNull("username")) null else user.getString("username"),
            deviceId = json.getString("device_id"),
            access = json.getString("access_token"),
            refresh = json.getString("refresh_token"),
        )
        sessions?.save(SessionSecrets(session.userId, session.deviceId, session.access, session.refresh))
        return session
    }

    fun logout() {
        sessions?.wipe()
    }

    data class Session(
        val userId: String,
        val username: String?,
        val deviceId: String,
        val access: String,
        val refresh: String,
    )

    companion object {
        /**
         * Authenticated client: 401 retries once via refresh, then wipes the
         * protocol store. [deviceJson] is still produced only by a bound engine.
         */
        fun connected(baseUrl: String, sessions: SessionController): AuthRepository {
            lateinit var api: OlloApi
            api = OlloApi(
                baseUrl,
                token = { sessions.access() },
                refresh = refresh@{
                    val token = sessions.refresh() ?: return@refresh false
                    val raw = try {
                        api.refreshSession(token)
                    } catch (_: Throwable) {
                        return@refresh false
                    }
                    val json = JSONObject(raw)
                    val access = json.optString("access_token")
                    val refreshTok = json.optString("refresh_token")
                    if (access.isEmpty() || refreshTok.isEmpty()) return@refresh false
                    sessions.applyRefresh(access, refreshTok)
                },
                onWipe = { sessions.wipe() },
            )
            return AuthRepository(api, sessions)
        }
    }
}

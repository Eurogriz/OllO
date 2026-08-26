package app.ollo.messenger.data

import app.ollo.crypto.SessionController
import app.ollo.crypto.SessionSecrets
import app.ollo.network.OlloApi
import org.json.JSONObject

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

    fun verify(challengeId: String, otp: String, deviceJson: String): Session {
        val body = JSONObject()
            .put("challenge_id", challengeId)
            .put("otp", otp)
            .put("device", JSONObject(deviceJson))
            .toString()
        val raw = api.post("/v1/auth/verify-otp", body, auth = false)
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

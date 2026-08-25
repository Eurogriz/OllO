package app.ollo.messenger.data

import app.ollo.network.OlloApi
import org.json.JSONObject

class AuthRepository(private val api: OlloApi) {
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
        return Session(
            userId = user.getString("id"),
            username = if (user.isNull("username")) null else user.getString("username"),
            deviceId = json.getString("device_id"),
            access = json.getString("access_token"),
            refresh = json.getString("refresh_token"),
        )
    }

    data class Session(
        val userId: String,
        val username: String?,
        val deviceId: String,
        val access: String,
        val refresh: String,
    )
}

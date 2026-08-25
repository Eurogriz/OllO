package app.ollo.network

import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.util.concurrent.TimeUnit

class OlloApi(
    private val baseUrl: String,
    private val token: () -> String?,
    private val refresh: (() -> Boolean)? = null,
    private val onWipe: (() -> Unit)? = null,
) {
    private val json = "application/json; charset=utf-8".toMediaType()
    private val http = OkHttpClient.Builder()
        .callTimeout(30, TimeUnit.SECONDS)
        .retryOnConnectionFailure(true)
        .build()

    fun requestOtp(phone: String): String {
        val body = """{"phone_e164":${JSONString(phone)}}"""
        return post("/v1/auth/request-otp", body, auth = false)
    }

    fun postEnvelopes(payload: String): String = post("/v1/envelopes", payload, auth = true)

    fun mailbox(): String = get("/v1/envelopes?limit=100")

    fun devicesOf(userId: String): String = get("/v1/keys/$userId/devices")

    fun consumeBundle(userId: String, deviceId: String): String = get("/v1/keys/$userId/$deviceId")

    fun peekBundle(userId: String, deviceId: String): String =
        get("/v1/keys/$userId/$deviceId?consume=0")

    fun searchUsername(username: String): String {
        val body = """{"username":${JSONString(username)}}"""
        return post("/v1/users/search", body, auth = true)
    }

    fun ack(idsJson: String): String = post("/v1/envelopes/ack", idsJson, auth = true)

    fun post(path: String, body: String, auth: Boolean): String {
        val builder = Request.Builder().url(baseUrl + path).post(body.toRequestBody(json))
        return execute(builder, auth)
    }

    private fun get(path: String): String {
        val builder = Request.Builder().url(baseUrl + path)
        return execute(builder, auth = true)
    }

    private fun execute(builder: Request.Builder, auth: Boolean, retried: Boolean = false): String {
        if (auth) token()?.let { builder.header("Authorization", "Bearer $it") }
        http.newCall(builder.build()).execute().use { res ->
            val t = res.body?.string().orEmpty()
            if (res.code == 401 && auth && !retried) {
                if (refresh?.invoke() == true) {
                    return execute(builder, auth, retried = true)
                }
                onWipe?.invoke()
            }
            if (!res.isSuccessful) error("http ${res.code}")
            return t
        }
    }
}

private fun JSONString(value: String): String =
    buildString {
        append('"')
        value.forEach { c ->
            when (c) {
                '\\' -> append("\\\\")
                '"' -> append("\\\"")
                '\n' -> append("\\n")
                else -> append(c)
            }
        }
        append('"')
    }

package app.ollo.crypto

/**
 * Access / refresh live in a dedicated wrapped slot. They are never written
 * into backups. Wipe this on logout, refresh reuse, and remote wipe.
 */
data class SessionSecrets(
    val userId: String,
    val deviceId: String,
    val access: String,
    val refresh: String,
)

class SessionVault(
    private val store: IdentityStore,
    private val wrapKey: ByteArray,
) {
    fun save(secrets: SessionSecrets) {
        store.put(
            wrapKey,
            KEY,
            BlobMap.encode(
                linkedMapOf(
                    "userId" to secrets.userId.toByteArray(Charsets.UTF_8),
                    "deviceId" to secrets.deviceId.toByteArray(Charsets.UTF_8),
                    "access" to secrets.access.toByteArray(Charsets.UTF_8),
                    "refresh" to secrets.refresh.toByteArray(Charsets.UTF_8),
                ),
            ),
        )
    }

    fun load(): SessionSecrets? {
        val raw = store.get(wrapKey, KEY) ?: return null
        val map = BlobMap.decode(raw)
        val userId = map["userId"]?.toString(Charsets.UTF_8) ?: return null
        val deviceId = map["deviceId"]?.toString(Charsets.UTF_8) ?: return null
        val access = map["access"]?.toString(Charsets.UTF_8) ?: return null
        val refresh = map["refresh"]?.toString(Charsets.UTF_8) ?: return null
        return SessionSecrets(userId, deviceId, access, refresh)
    }

    fun clear() {
        store.remove(KEY)
    }

    companion object {
        const val KEY = "session.v1"
    }
}

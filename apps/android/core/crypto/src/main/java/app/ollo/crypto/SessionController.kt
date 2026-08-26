package app.ollo.crypto

/**
 * In-memory access/refresh plus the wrapped [SessionVault]. Tokens never go
 * into backups. A failed refresh wipes identity, sessions, and history.
 */
class SessionController(private val proto: ProtocolStore) {
    private val vault = proto.sessionVault
    var secrets: SessionSecrets? = null
        private set

    fun access(): String? = secrets?.access

    fun refresh(): String? = secrets?.refresh

    fun restore(): SessionSecrets? {
        secrets = vault.load()
        return secrets
    }

    fun save(next: SessionSecrets) {
        vault.save(next)
        secrets = next
    }

    fun applyRefresh(access: String, refresh: String): Boolean {
        val cur = secrets ?: return false
        save(cur.copy(access = access, refresh = refresh))
        return true
    }

    fun onUnauthorized(refreshSucceeded: Boolean): EnvelopePlanner.AuthFailure {
        val action = EnvelopePlanner.afterUnauthorized(refreshSucceeded)
        if (action == EnvelopePlanner.AuthFailure.Wipe) wipe()
        return action
    }

    fun wipe() {
        secrets = null
        proto.wipe()
    }
}

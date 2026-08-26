package app.ollo.messenger

import android.content.Context
import app.ollo.crypto.AccountKey
import app.ollo.crypto.CryptoEngine
import app.ollo.crypto.DevicePayload
import app.ollo.crypto.EnvelopePlanner
import app.ollo.crypto.IdentityStore
import app.ollo.crypto.LibsignalEngine
import app.ollo.crypto.ProtocolStore
import app.ollo.crypto.SessionController
import app.ollo.crypto.ThreadIndex
import app.ollo.messenger.crypto.DbKeyProvider
import app.ollo.messenger.data.AuthRepository
import java.io.File

/**
 * Process-lifetime session host. Protocol blobs live under [Context.noBackupFilesDir]
 * and are wrapped by Android Keystore. Tokens restore from [SessionController].
 * Default engine is store-backed [LibsignalEngine]. Tests may inject
 * [app.ollo.crypto.UnboundCryptoEngine]. This host never invents
 * `registration_id` or prekey ids.
 */
class SessionHost(
    val proto: ProtocolStore,
    val sessions: SessionController,
    val auth: AuthRepository,
    val engine: CryptoEngine,
) {
    fun launch(): EnvelopePlanner.SessionLaunch = sessions.launch()

    fun loadInbox(): ThreadIndex = proto.loadThreads()

    fun account(): AccountKey = proto.accountVault.getOrCreate()

    fun wipe() {
        sessions.wipe()
    }

    /**
     * Fail closed before burning an OTP. A bound engine emits the official
     * device JSON; [UnboundCryptoEngine] throws.
     */
    fun requireRegistration(name: String, platform: String): String =
        DevicePayload.requireRegistration(engine, name, platform)

    companion object {
        const val STORE_DIR = "ollo-proto"

        fun open(
            store: IdentityStore,
            wrapKey: ByteArray,
            engine: CryptoEngine? = null,
            baseUrl: String,
        ): SessionHost {
            require(wrapKey.size == 32) { "protocol wrap unavailable" }
            val proto = ProtocolStore(store, wrapKey)
            val sessions = SessionController(proto)
            return SessionHost(
                proto = proto,
                sessions = sessions,
                auth = AuthRepository.connected(baseUrl, sessions),
                engine = engine ?: LibsignalEngine.create(proto),
            )
        }

        fun open(context: Context, engine: CryptoEngine? = null): SessionHost {
            val dir = File(context.noBackupFilesDir, STORE_DIR)
            if (!dir.exists() && !dir.mkdirs()) {
                throw IllegalStateException("protocol store directory unavailable")
            }
            return open(
                store = IdentityStore(directory = dir),
                wrapKey = DbKeyProvider(context).getOrCreate(),
                engine = engine,
                baseUrl = BuildConfig.API_BASE,
            )
        }
    }
}

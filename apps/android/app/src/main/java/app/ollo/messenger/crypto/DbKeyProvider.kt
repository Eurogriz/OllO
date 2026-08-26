package app.ollo.messenger.crypto

import android.content.Context
import java.io.File
import java.security.SecureRandom

/**
 * 32-byte SQLCipher passphrase, wrapped by Android Keystore (AES-GCM, AAD
 * `ollo-wrap-v1`). The wrapped blob lives in noBackupFilesDir; the wrapping
 * key never leaves Keystore / StrongBox.
 */
class DbKeyProvider(
    private val context: Context,
    private val keystore: AndroidKeyStore = AndroidKeyStore(),
) {
    private val wrapFile = File(context.noBackupFilesDir, "ollo.db.wrap")

    fun getOrCreate(): ByteArray {
        if (wrapFile.exists()) {
            return keystore.unwrap(wrapFile.readBytes())
        }
        val raw = ByteArray(32)
        SecureRandom().nextBytes(raw)
        wrapFile.writeBytes(keystore.wrap(raw))
        return raw
    }

    fun wipe() {
        if (wrapFile.exists()) {
            wrapFile.writeBytes(ByteArray(wrapFile.length().toInt().coerceAtMost(64)))
            wrapFile.delete()
        }
        keystore.delete()
    }
}

package app.ollo.messenger.crypto

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Wraps the SQLCipher / identity blob key in Android Keystore.
 * Prefers StrongBox when the device exposes it.
 */
class AndroidKeyStore(private val alias: String = "ollo.db.wrap.v1") {
    private val ks: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    fun getOrCreate(): SecretKey {
        (ks.getKey(alias, null) as? SecretKey)?.let { return it }
        val spec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(false)
            .apply {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    setIsStrongBoxBacked(true)
                }
            }
            .build()
        return try {
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").run {
                init(spec)
                generateKey()
            }
        } catch (_: Exception) {
            val fallback = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").run {
                init(fallback)
                generateKey()
            }
        }
    }

    fun wrap(raw: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, getOrCreate())
        c.updateAAD(AAD)
        return c.iv + c.doFinal(raw)
    }

    fun unwrap(blob: ByteArray): ByteArray {
        val iv = blob.copyOfRange(0, 12)
        val ct = blob.copyOfRange(12, blob.size)
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, getOrCreate(), GCMParameterSpec(128, iv))
        c.updateAAD(AAD)
        return c.doFinal(ct)
    }

    fun delete() {
        if (ks.containsAlias(alias)) ks.deleteEntry(alias)
    }

    companion object {
        private val AAD = "ollo-wrap-v1".toByteArray(Charsets.UTF_8)
    }
}

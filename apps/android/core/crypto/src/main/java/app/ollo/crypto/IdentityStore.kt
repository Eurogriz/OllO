package app.ollo.crypto

import java.io.File

/**
 * Encrypted identity / session / outbox / prekey blobs. The wrapping key never
 * lives next to the ciphertext: on device it comes from Android Keystore;
 * tests inject a software key.
 *
 * Optional [directory] persists already-wrapped files (one per key) so a
 * process restart does not drop ratchet state. Wipe shreds memory and files.
 */
class IdentityStore(
    private val kv: MutableMap<String, ByteArray> = linkedMapOf(),
    private val directory: File? = null,
) {
    init {
        directory?.mkdirs()
        directory?.listFiles()?.forEach { f ->
            if (f.isFile && !f.name.endsWith(".tmp") && !kv.containsKey(f.name)) {
                kv[f.name] = f.readBytes()
            }
        }
    }

    fun put(wrapKey: ByteArray, slot: Slot, plaintext: ByteArray) {
        put(wrapKey, slot.key, plaintext)
    }

    fun put(wrapKey: ByteArray, key: String, plaintext: ByteArray) {
        assertSafeStoreKey(key)
        val sealed = AesGcmWrap.seal(wrapKey, plaintext)
        kv[key] = sealed
        writeFile(key, sealed)
    }

    fun get(wrapKey: ByteArray, slot: Slot): ByteArray? = get(wrapKey, slot.key)

    fun get(wrapKey: ByteArray, key: String): ByteArray? {
        assertSafeStoreKey(key)
        val blob = kv[key] ?: return null
        return AesGcmWrap.open(wrapKey, blob)
    }

    fun remove(key: String) {
        assertSafeStoreKey(key)
        kv[key]?.fill(0)
        kv.remove(key)
        directory?.let { File(it, key).delete() }
    }

    fun keys(prefix: String = ""): List<String> = kv.keys.filter { it.startsWith(prefix) }.sorted()

    fun wipe(): Int {
        val n = kv.size
        kv.keys.toList().forEach { k ->
            kv[k]?.fill(0)
            kv.remove(k)
        }
        kv.clear()
        directory?.listFiles()?.forEach { f ->
            if (f.isFile) {
                val nBytes = f.length().toInt().coerceAtMost(4096)
                if (nBytes > 0) f.writeBytes(ByteArray(nBytes))
                f.delete()
            }
        }
        return n
    }

    fun isEmpty(): Boolean = kv.isEmpty()

    private fun writeFile(key: String, sealed: ByteArray) {
        val dir = directory ?: return
        val target = File(dir, key)
        val tmp = File(dir, "$key.tmp")
        tmp.writeBytes(sealed)
        if (target.exists()) target.delete()
        if (!tmp.renameTo(target)) {
            target.writeBytes(sealed)
            tmp.delete()
        }
    }

    enum class Slot(val key: String) {
        Identity("identity.v1"),
        Sessions("sessions.v1"),
        Outbox("outbox.v1"),
        SenderKeys("senderkeys.v1"),
        KnownIdentities("known.v1"),
        PreKeys("prekeys.v1"),
        SignedPreKeys("signedprekeys.v1"),
        Threads("threads.v1"),
    }
}

internal fun assertSafeStoreKey(key: String) {
    require(key.isNotEmpty()) { "empty store key" }
    require(key.none { it == '/' || it == '\\' || it == '\u0000' }) { "unsafe store key" }
    require(!key.contains("..")) { "unsafe store key" }
}

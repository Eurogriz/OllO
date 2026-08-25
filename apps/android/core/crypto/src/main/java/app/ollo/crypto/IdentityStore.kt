package app.ollo.crypto

/**
 * Encrypted identity / session / outbox blobs. The wrapping key never
 * lives next to the ciphertext: on device it comes from Android Keystore;
 * tests inject a software key.
 *
 * Wipe drops every secret. Call this on logout, device revoke, and remote wipe.
 */
class IdentityStore(
    private val kv: MutableMap<String, ByteArray> = linkedMapOf(),
) {
    fun put(wrapKey: ByteArray, slot: Slot, plaintext: ByteArray) {
        kv[slot.key] = AesGcmWrap.seal(wrapKey, plaintext)
    }

    fun get(wrapKey: ByteArray, slot: Slot): ByteArray? {
        val blob = kv[slot.key] ?: return null
        return AesGcmWrap.open(wrapKey, blob)
    }

    fun wipe(): Int {
        val n = kv.size
        kv.keys.toList().forEach { k ->
            kv[k]?.fill(0)
            kv.remove(k)
        }
        kv.clear()
        return n
    }

    fun isEmpty(): Boolean = kv.isEmpty()

    enum class Slot(val key: String) {
        Identity("identity.v1"),
        Sessions("sessions.v1"),
        Outbox("outbox.v1"),
        SenderKeys("senderkeys.v1"),
        KnownIdentities("known.v1"),
    }
}

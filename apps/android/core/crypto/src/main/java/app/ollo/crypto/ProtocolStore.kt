package app.ollo.crypto

/**
 * Durable opaque store for official libsignal records. This class does not
 * ratcheting-encrypt: it only keeps what SessionCipher / KeyHelper produce,
 * under [IdentityStore] AES-GCM.
 *
 * Do not import unverified `org.signal.libsignal` types here. Bind the
 * engine later; the records stay raw bytes.
 */
class ProtocolStore(
    val store: IdentityStore,
    private val wrapKey: ByteArray,
    localUserId: String = "",
    localDeviceId: String = "",
) {
    val sessions = SessionDirectory(store, wrapKey, localUserId, localDeviceId)
    val messages = MessageLog(store, wrapKey)
    val sessionVault = SessionVault(store, wrapKey)
    val accountVault = AccountVault(store, wrapKey)

    fun storeLocalIdentity(
        record: ByteArray,
        registrationId: Int,
        extras: Map<String, ByteArray> = emptyMap(),
    ) {
        require(registrationId in 1..0x3FFF) { "registration id out of range" }
        val map = linkedMapOf(
            "record" to record.copyOf(),
            "registration_id" to be32(registrationId),
        )
        for ((k, v) in extras) map[k] = v.copyOf()
        persist(IdentityStore.Slot.Identity, map)
    }

    fun loadLocalIdentity(): ByteArray? = loadMap(IdentityStore.Slot.Identity)["record"]

    fun loadIdentityField(name: String): ByteArray? = loadMap(IdentityStore.Slot.Identity)[name]

    fun preKeyIds(): List<Int> =
        loadMap(IdentityStore.Slot.PreKeys).keys.mapNotNull { it.toIntOrNull() }.sorted()

    fun signedPreKeyIds(): List<Int> =
        loadMap(IdentityStore.Slot.SignedPreKeys).keys.mapNotNull { it.toIntOrNull() }.sorted()

    fun registrationId(): Int? {
        val raw = loadMap(IdentityStore.Slot.Identity)["registration_id"] ?: return null
        if (raw.size != 4) return null
        return ((raw[0].toInt() and 0xff) shl 24) or
            ((raw[1].toInt() and 0xff) shl 16) or
            ((raw[2].toInt() and 0xff) shl 8) or
            (raw[3].toInt() and 0xff)
    }

    fun storePreKey(id: Int, record: ByteArray) {
        val map = loadMap(IdentityStore.Slot.PreKeys)
        map[id.toString()] = record.copyOf()
        persist(IdentityStore.Slot.PreKeys, map)
    }

    fun loadPreKey(id: Int): ByteArray? = loadMap(IdentityStore.Slot.PreKeys)[id.toString()]

    fun removePreKey(id: Int) {
        val map = loadMap(IdentityStore.Slot.PreKeys)
        map.remove(id.toString())
        persist(IdentityStore.Slot.PreKeys, map)
    }

    fun storeSignedPreKey(id: Int, record: ByteArray) {
        val map = loadMap(IdentityStore.Slot.SignedPreKeys)
        map[id.toString()] = record.copyOf()
        persist(IdentityStore.Slot.SignedPreKeys, map)
    }

    fun loadSignedPreKey(id: Int): ByteArray? = loadMap(IdentityStore.Slot.SignedPreKeys)[id.toString()]

    /** Drop retired signed prekeys beyond the keep-last-2 window. */
    fun pruneSignedPreKeys(currentId: Int) {
        val map = loadMap(IdentityStore.Slot.SignedPreKeys)
        val keep = EnvelopePlanner.keepSignedPrekeyIds(
            currentId,
            map.keys.mapNotNull { it.toIntOrNull() },
        ).toSet()
        val next = linkedMapOf<String, ByteArray>()
        for ((k, v) in map) {
            val id = k.toIntOrNull() ?: continue
            if (id in keep) next[k] = v
        }
        persist(IdentityStore.Slot.SignedPreKeys, next)
    }

    fun saveThreads(index: ThreadIndex) {
        store.put(wrapKey, IdentityStore.Slot.Threads, index.encode())
    }

    fun loadThreads(): ThreadIndex {
        val raw = store.get(wrapKey, IdentityStore.Slot.Threads) ?: return ThreadIndex()
        return ThreadIndex.decode(raw)
    }

    fun saveOutboxItem(id: String, payload: ByteArray) {
        val map = loadMap(IdentityStore.Slot.Outbox)
        map[id] = payload.copyOf()
        persist(IdentityStore.Slot.Outbox, map)
    }

    fun loadOutbox(): Map<String, ByteArray> = loadMap(IdentityStore.Slot.Outbox)

    fun removeOutboxItem(id: String) {
        val map = loadMap(IdentityStore.Slot.Outbox)
        map.remove(id)
        persist(IdentityStore.Slot.Outbox, map)
    }

    fun planFetch(targetUserId: String, targetDeviceId: String): EnvelopePlanner.KeyPlan =
        sessions.planFetch(targetUserId, targetDeviceId)

    fun rememberEnvelope(envelopeId: String): EnvelopePlanner.ReplayDecision {
        val map = loadMap(IdentityStore.Slot.Replay)
        val ids = ArrayList<String>()
        val raw = map["ids"]
        if (raw != null && raw.isNotEmpty()) {
            ids.addAll(String(raw, Charsets.UTF_8).split('\n').filter { it.isNotEmpty() })
        }
        val decision = EnvelopePlanner.rememberEnvelope(ids, envelopeId)
        if (decision == EnvelopePlanner.ReplayDecision.Accept) {
            persist(
                IdentityStore.Slot.Replay,
                linkedMapOf("ids" to ids.joinToString("\n").toByteArray(Charsets.UTF_8)),
            )
        }
        return decision
    }

    fun wipe() {
        store.wipe()
    }

    private fun loadMap(slot: IdentityStore.Slot): LinkedHashMap<String, ByteArray> {
        val raw = store.get(wrapKey, slot) ?: return linkedMapOf()
        return BlobMap.decode(raw)
    }

    private fun persist(slot: IdentityStore.Slot, map: Map<String, ByteArray>) {
        store.put(wrapKey, slot, BlobMap.encode(map))
    }

    private fun be32(n: Int): ByteArray = byteArrayOf(
        ((n ushr 24) and 0xff).toByte(),
        ((n ushr 16) and 0xff).toByte(),
        ((n ushr 8) and 0xff).toByte(),
        (n and 0xff).toByte(),
    )
}

package app.ollo.crypto

/**
 * Encrypted directory of opaque libsignal session records and remote
 * identity fingerprints. This class does not ratcheting-encrypt: it only
 * stores what SessionCipher produces, under [IdentityStore] AES-GCM.
 */
class SessionDirectory(
    private val store: IdentityStore,
    private val wrapKey: ByteArray,
    var localUserId: String = "",
    var localDeviceId: String = "",
) {
    enum class IdentityDecision { New, Unchanged, Changed }

    data class Address(val userId: String, val deviceId: String) {
        fun key(): String = "$userId:$deviceId"
    }

    fun hasSession(address: Address): Boolean = sessions().containsKey(address.key())

    fun loadSession(address: Address): ByteArray? = sessions()[address.key()]

    fun saveSession(address: Address, record: ByteArray) {
        val map = sessions()
        map[address.key()] = record
        persist(IdentityStore.Slot.Sessions, map)
    }

    fun deleteSession(address: Address) {
        val map = sessions()
        map.remove(address.key())
        persist(IdentityStore.Slot.Sessions, map)
    }

    fun sessionKeys(): List<String> = sessions().keys.toList()

    /** Drop ratchet records for devices that left [userId]'s live roster. */
    fun dropStale(userId: String, liveDeviceIds: Collection<String>) {
        val drop = EnvelopePlanner.planRosterPrune(sessionKeys(), userId, liveDeviceIds)
        if (drop.isEmpty()) return
        val sess = sessions()
        val known = identities()
        for (k in drop) {
            sess.remove(k)
            known.remove(k)
        }
        persist(IdentityStore.Slot.Sessions, sess)
        persist(IdentityStore.Slot.KnownIdentities, known)
    }

    fun planFetch(targetUserId: String, targetDeviceId: String): EnvelopePlanner.KeyPlan {
        return EnvelopePlanner.planKeyFetch(
            localUserId = localUserId,
            localDeviceId = localDeviceId,
            targetUserId = targetUserId,
            targetDeviceId = targetDeviceId,
            hasSession = hasSession(Address(targetUserId, targetDeviceId)),
        )
    }

    fun noteRemoteIdentity(address: Address, identityX25519: ByteArray): IdentityDecision {
        val map = identities()
        val prev = map[address.key()]
        if (prev == null) {
            map[address.key()] = identityX25519.copyOf()
            persist(IdentityStore.Slot.KnownIdentities, map)
            return IdentityDecision.New
        }
        if (prev.contentEquals(identityX25519)) return IdentityDecision.Unchanged
        return IdentityDecision.Changed
    }

    /** Overwrite only after the user re-verifies a changed safety number. */
    fun replaceRemoteIdentity(address: Address, identityX25519: ByteArray) {
        val map = identities()
        map[address.key()] = identityX25519.copyOf()
        persist(IdentityStore.Slot.KnownIdentities, map)
    }

    fun wipe() {
        store.wipe()
    }

    private fun sessions(): LinkedHashMap<String, ByteArray> = load(IdentityStore.Slot.Sessions)

    private fun identities(): LinkedHashMap<String, ByteArray> = load(IdentityStore.Slot.KnownIdentities)

    private fun load(slot: IdentityStore.Slot): LinkedHashMap<String, ByteArray> {
        val raw = store.get(wrapKey, slot) ?: return linkedMapOf()
        return BlobMap.decode(raw)
    }

    private fun persist(slot: IdentityStore.Slot, map: Map<String, ByteArray>) {
        store.put(wrapKey, slot, BlobMap.encode(map))
    }
}

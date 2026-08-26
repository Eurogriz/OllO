package app.ollo.crypto

/**
 * Long-term account Ed25519 lives in its own wrapped slot. Generating a new
 * [AccountKey] on every unsigned launch would mint a new account each tap.
 */
class AccountVault(
    private val store: IdentityStore,
    private val wrapKey: ByteArray,
) {
    fun save(key: AccountKey) {
        store.put(
            wrapKey,
            IdentityStore.Slot.Account,
            BlobMap.encode(
                linkedMapOf(
                    "seed" to key.privateSeed.copyOf(),
                    "public" to key.publicKey.copyOf(),
                ),
            ),
        )
    }

    fun load(): AccountKey? {
        val raw = store.get(wrapKey, IdentityStore.Slot.Account) ?: return null
        val map = BlobMap.decode(raw)
        val seed = map["seed"] ?: return null
        val pub = map["public"] ?: return null
        return AccountKey.fromSeed(seed, pub)
    }

    fun getOrCreate(): AccountKey {
        load()?.let { return it }
        val next = AccountKey.generate()
        save(next)
        return next
    }
}

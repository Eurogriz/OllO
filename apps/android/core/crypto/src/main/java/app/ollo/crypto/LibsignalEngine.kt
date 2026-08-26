package app.ollo.crypto

import android.util.Base64
import com.google.crypto.tink.subtle.Ed25519Sign
import org.json.JSONArray
import org.json.JSONObject
import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.IdentityKeyPair
import org.signal.libsignal.protocol.InvalidMessageException
import org.signal.libsignal.protocol.SessionBuilder
import org.signal.libsignal.protocol.SessionCipher
import org.signal.libsignal.protocol.SignalProtocolAddress
import org.signal.libsignal.protocol.ecc.Curve
import org.signal.libsignal.protocol.message.PreKeySignalMessage
import org.signal.libsignal.protocol.message.SignalMessage
import org.signal.libsignal.protocol.state.PreKeyBundle
import org.signal.libsignal.protocol.state.PreKeyRecord
import org.signal.libsignal.protocol.state.SessionRecord
import org.signal.libsignal.protocol.state.SignedPreKeyRecord
import org.signal.libsignal.protocol.state.impl.InMemorySignalProtocolStore
import org.signal.libsignal.protocol.util.KeyHelper
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Official libsignal (0.58.1) for **device** sessions.
 *
 * Account proofs stay on [AccountKey] (Tink Ed25519). libsignal IdentityKey
 * is XEdDSA and must not sign `ollo-auth-v1` or the published
 * `signed_prekey.signature` that the server verifies with noble Ed25519.
 *
 * Published `identity_key_x25519` is the libsignal identity with the 0x05
 * prefix stripped (OllO directory is 32 bytes). SessionBuilder needs the
 * XEdDSA signature of the signed prekey; that lives in `signed_prekey.xeddsa`
 * and is echoed by the directory without noble verification.
 *
 * Identity, prekeys, and session records are written into [ProtocolStore]
 * when one is bound so a process restart does not remint or drop ratchets.
 *
 * This is not a Signal-level security claim.
 */
class LibsignalEngine private constructor(
    private val identity: IdentityKeyPair,
    private val registrationId: Int,
    private val deviceEd25519Seed: ByteArray,
    private val deviceEd25519Public: ByteArray,
    private val proto: ProtocolStore?,
) : CryptoEngine {
    private val store = InMemorySignalProtocolStore(identity, registrationId)
    private val sessions = ConcurrentHashMap<String, SignalProtocolAddress>()
    private val lock = Any()
    private var published: PublishedKeys? = null

    override fun generateIdentity(): IdentityMaterial = mintIfNeeded().material

    override fun deviceRegistrationJson(name: String, platform: String): String {
        val pub = mintIfNeeded()
        val opks = JSONArray()
        for ((id, publicKey) in pub.oneTime) {
            opks.put(JSONObject().put("id", id).put("public", b64(publicKey)))
        }
        return JSONObject()
            .put("name", name)
            .put("platform", platform)
            .put("registration_id", registrationId)
            .put("identity_key_x25519", b64(stripDjb(identity.publicKey.serialize())))
            .put("identity_key_ed25519", b64(deviceEd25519Public))
            .put(
                "signed_prekey",
                JSONObject()
                    .put("id", pub.signedId)
                    .put("public", b64(pub.spkPub))
                    .put("signature", b64(pub.edSig))
                    .put("xeddsa", b64(pub.xeddsa)),
            )
            .put("one_time_prekeys", opks)
            .toString()
    }

    override fun existingSession(userId: String, deviceId: String): SessionHandle? {
        val address = SignalProtocolAddress("$userId:$deviceId", 1)
        if (!store.containsSession(address)) return null
        return remember(address)
    }

    override fun processPrekeyBundle(remote: ByteArray): SessionHandle {
        val json = JSONObject(String(remote, Charsets.UTF_8))
        val userId = json.getString("user_id")
        val deviceId = json.getString("device_id")
        val address = SignalProtocolAddress("$userId:$deviceId", 1)
        if (store.containsSession(address)) return remember(address)
        val identityKey = IdentityKey(prefixDjb(b64d(json.getString("identity_key_x25519"))), 0)
        val spk = json.getJSONObject("signed_prekey")
        val xeddsa = when {
            spk.has("xeddsa") && !spk.isNull("xeddsa") -> b64d(spk.getString("xeddsa"))
            json.has("xeddsa") -> b64d(json.getString("xeddsa"))
            else -> throw IllegalArgumentException("missing libsignal signed prekey signature")
        }
        val opk = if (json.isNull("one_time_prekey")) null else json.optJSONObject("one_time_prekey")
        val bundle = PreKeyBundle(
            json.getInt("registration_id"),
            1,
            opk?.getInt("id") ?: 0,
            opk?.let { Curve.decodePoint(prefixDjb(b64d(it.getString("public"))), 0) },
            spk.getInt("id"),
            Curve.decodePoint(prefixDjb(b64d(spk.getString("public"))), 0),
            xeddsa,
            identityKey,
        )
        SessionBuilder(store, address).process(bundle)
        persistSession(address)
        proto?.sessions?.noteRemoteIdentity(
            SessionDirectory.Address(userId, deviceId),
            stripDjb(identityKey.serialize()),
        )
        return remember(address)
    }

    override fun encrypt(session: SessionHandle, plaintext: ByteArray): ByteArray {
        val address = sessions[session.id] ?: throw IllegalStateException("unknown session")
        val out = SessionCipher(store, address).encrypt(plaintext).serialize()
        persistSession(address)
        return out
    }

    override fun decrypt(session: SessionHandle, payload: ByteArray): ByteArray {
        val address = sessions[session.id] ?: throw IllegalStateException("unknown session")
        val cipher = SessionCipher(store, address)
        val out = try {
            cipher.decrypt(PreKeySignalMessage(payload))
        } catch (_: InvalidMessageException) {
            cipher.decrypt(SignalMessage(payload))
        }
        persistSession(address)
        return out
    }

    override fun safetyNumber(localIdentity: ByteArray, remoteIdentity: ByteArray): String =
        SafetyNumber.of(localIdentity, remoteIdentity).digits

    /** Device Ed25519 (Tink). Account proofs must use [AccountKey.sign]. */
    override fun sign(message: ByteArray): ByteArray = Ed25519Sign(deviceEd25519Seed).sign(message)

    private fun mintIfNeeded(): PublishedKeys {
        published?.let { return it }
        synchronized(lock) {
            published?.let { return it }
            restorePublished()?.let {
                published = it
                return it
            }
            val signed = KeyHelper.generateSignedPreKey(identity, 1)
            store.storeSignedPreKey(signed.id, signed)
            val oneTime = KeyHelper.generatePreKeys(1, 100)
            for (k in oneTime) store.storePreKey(k.id, k)
            val spkPub = stripDjb(signed.keyPair.publicKey.serialize())
            val edSig = Ed25519Sign(deviceEd25519Seed).sign(spkPub)
            proto?.storeSignedPreKey(signed.id, signed.serialize())
            proto?.pruneSignedPreKeys(signed.id)
            for (k in oneTime) proto?.storePreKey(k.id, k.serialize())
            proto?.storeLocalIdentity(
                identity.serialize(),
                registrationId,
                linkedMapOf(
                    "device_ed25519_seed" to deviceEd25519Seed,
                    "device_ed25519_public" to deviceEd25519Public,
                    "spk_ed25519_sig" to edSig,
                ),
            )
            val next = PublishedKeys(
                signedId = signed.id,
                spkPub = spkPub,
                edSig = edSig,
                xeddsa = signed.signature,
                oneTime = oneTime.map { it.id to stripDjb(it.keyPair.publicKey.serialize()) },
                material = IdentityMaterial(
                    identityX25519 = stripDjb(identity.publicKey.serialize()),
                    identityEd25519 = deviceEd25519Public.copyOf(),
                    signedPrekey = spkPub,
                    signedPrekeySignature = edSig,
                    oneTimePrekeys = oneTime.map { stripDjb(it.keyPair.publicKey.serialize()) },
                ),
            )
            published = next
            return next
        }
    }

    private fun restorePublished(): PublishedKeys? {
        val proto = proto ?: return null
        val ids = proto.signedPreKeyIds()
        val currentId = ids.maxOrNull() ?: return null
        val raw = proto.loadSignedPreKey(currentId) ?: return null
        val signed = SignedPreKeyRecord(raw)
        store.storeSignedPreKey(signed.id, signed)
        val oneTime = ArrayList<Pair<Int, ByteArray>>()
        for (id in proto.preKeyIds()) {
            val recRaw = proto.loadPreKey(id) ?: continue
            val rec = PreKeyRecord(recRaw)
            store.storePreKey(rec.id, rec)
            oneTime.add(rec.id to stripDjb(rec.keyPair.publicKey.serialize()))
        }
        val spkPub = stripDjb(signed.keyPair.publicKey.serialize())
        val edSig = proto.loadIdentityField("spk_ed25519_sig") ?: return null
        return PublishedKeys(
            signedId = signed.id,
            spkPub = spkPub,
            edSig = edSig,
            xeddsa = signed.signature,
            oneTime = oneTime,
            material = IdentityMaterial(
                identityX25519 = stripDjb(identity.publicKey.serialize()),
                identityEd25519 = deviceEd25519Public.copyOf(),
                signedPrekey = spkPub,
                signedPrekeySignature = edSig,
                oneTimePrekeys = oneTime.map { it.second },
            ),
        )
    }

    private fun restoreSessions() {
        val proto = proto ?: return
        for (key in proto.sessions.sessionKeys()) {
            val parts = parseAddressKey(key) ?: continue
            val raw = proto.sessions.loadSession(parts) ?: continue
            val address = SignalProtocolAddress(key, 1)
            store.storeSession(address, SessionRecord(raw))
        }
    }

    private fun persistSession(address: SignalProtocolAddress) {
        val proto = proto ?: return
        val rec = store.loadSession(address)
        val parts = parseAddressKey(address.name) ?: return
        proto.sessions.saveSession(parts, rec.serialize())
    }

    private fun remember(address: SignalProtocolAddress): SessionHandle {
        val handle = SessionHandle(UUID.randomUUID().toString())
        sessions[handle.id] = address
        return handle
    }

    private data class PublishedKeys(
        val signedId: Int,
        val spkPub: ByteArray,
        val edSig: ByteArray,
        val xeddsa: ByteArray,
        val oneTime: List<Pair<Int, ByteArray>>,
        val material: IdentityMaterial,
    )

    companion object {
        const val DJB_TYPE: Byte = 0x05

        fun create(proto: ProtocolStore? = null): LibsignalEngine {
            val record = proto?.loadLocalIdentity()
            val reg = proto?.registrationId()
            val seed = proto?.loadIdentityField("device_ed25519_seed")
            val pub = proto?.loadIdentityField("device_ed25519_public")
            val engine = if (record != null && reg != null && seed != null && pub != null) {
                LibsignalEngine(IdentityKeyPair(record), reg, seed, pub, proto)
            } else {
                val pair = Ed25519Sign.KeyPair.newKeyPair()
                val next = LibsignalEngine(
                    IdentityKeyPair.generate(),
                    KeyHelper.generateRegistrationId(false),
                    pair.privateKey.copyOf(),
                    pair.publicKey.copyOf(),
                    proto,
                )
                proto?.storeLocalIdentity(
                    next.identity.serialize(),
                    next.registrationId,
                    linkedMapOf(
                        "device_ed25519_seed" to next.deviceEd25519Seed,
                        "device_ed25519_public" to next.deviceEd25519Public,
                    ),
                )
                next
            }
            engine.restoreSessions()
            return engine
        }

        fun stripDjb(serialized: ByteArray): ByteArray {
            require(serialized.size == 33 && serialized[0] == DJB_TYPE) { "expected 33-byte DJB public key" }
            return serialized.copyOfRange(1, 33)
        }

        fun prefixDjb(raw32: ByteArray): ByteArray {
            require(raw32.size == 32) { "expected 32-byte public key" }
            return byteArrayOf(DJB_TYPE) + raw32
        }

        internal fun parseAddressKey(name: String): SessionDirectory.Address? {
            val i = name.indexOf(':')
            if (i <= 0 || i == name.lastIndex) return null
            return SessionDirectory.Address(name.substring(0, i), name.substring(i + 1))
        }

        private fun b64(bytes: ByteArray): String = Base64.encodeToString(bytes, Base64.NO_WRAP)

        private fun b64d(s: String): ByteArray = Base64.decode(s, Base64.DEFAULT)
    }
}

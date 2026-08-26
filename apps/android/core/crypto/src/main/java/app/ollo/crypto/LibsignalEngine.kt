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
import org.signal.libsignal.protocol.ecc.ECPublicKey
import org.signal.libsignal.protocol.message.PreKeySignalMessage
import org.signal.libsignal.protocol.message.SignalMessage
import org.signal.libsignal.protocol.state.PreKeyBundle
import org.signal.libsignal.protocol.state.PreKeyRecord
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
 * and is ignored by the server.
 *
 * This is not a Signal-level security claim.
 */
class LibsignalEngine(
    private val identity: IdentityKeyPair = IdentityKeyPair.generate(),
    private val registrationId: Int = KeyHelper.generateRegistrationId(false),
    private val deviceEd25519: Ed25519Sign.KeyPair = Ed25519Sign.KeyPair.newKeyPair(),
) : CryptoEngine {
    private val store = InMemorySignalProtocolStore(identity, registrationId)
    private val sessions = ConcurrentHashMap<String, SignalProtocolAddress>()

    override fun generateIdentity(): IdentityMaterial {
        val signed = KeyHelper.generateSignedPreKey(identity, 1)
        store.storeSignedPreKey(signed.id, signed)
        val oneTime = KeyHelper.generatePreKeys(1, 100)
        for (k in oneTime) store.storePreKey(k.id, k)
        val spkPub = stripDjb(signed.keyPair.publicKey.serialize())
        val edSig = Ed25519Sign(deviceEd25519.privateKey).sign(spkPub)
        return IdentityMaterial(
            identityX25519 = stripDjb(identity.publicKey.serialize()),
            identityEd25519 = deviceEd25519.publicKey.copyOf(),
            signedPrekey = spkPub,
            signedPrekeySignature = edSig,
            oneTimePrekeys = oneTime.map { stripDjb(it.keyPair.publicKey.serialize()) },
        )
    }

    override fun deviceRegistrationJson(name: String, platform: String): String {
        val signed = KeyHelper.generateSignedPreKey(identity, 1)
        store.storeSignedPreKey(signed.id, signed)
        val oneTime = KeyHelper.generatePreKeys(1, 100)
        for (k in oneTime) store.storePreKey(k.id, k)
        val spkPub = stripDjb(signed.keyPair.publicKey.serialize())
        val edSig = Ed25519Sign(deviceEd25519.privateKey).sign(spkPub)
        val opks = JSONArray()
        for (k in oneTime) {
            opks.put(
                JSONObject()
                    .put("id", k.id)
                    .put("public", b64(stripDjb(k.keyPair.publicKey.serialize()))),
            )
        }
        return JSONObject()
            .put("name", name)
            .put("platform", platform)
            .put("registration_id", registrationId)
            .put("identity_key_x25519", b64(stripDjb(identity.publicKey.serialize())))
            .put("identity_key_ed25519", b64(deviceEd25519.publicKey))
            .put(
                "signed_prekey",
                JSONObject()
                    .put("id", signed.id)
                    .put("public", b64(spkPub))
                    .put("signature", b64(edSig))
                    .put("xeddsa", b64(signed.signature)),
            )
            .put("one_time_prekeys", opks)
            .toString()
    }

    override fun processPrekeyBundle(remote: ByteArray): SessionHandle {
        val json = JSONObject(String(remote, Charsets.UTF_8))
        val userId = json.getString("user_id")
        val deviceId = json.getString("device_id")
        val address = SignalProtocolAddress("$userId:$deviceId", 1)
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
        val handle = SessionHandle(UUID.randomUUID().toString())
        sessions[handle.id] = address
        return handle
    }

    override fun encrypt(session: SessionHandle, plaintext: ByteArray): ByteArray {
        val address = sessions[session.id] ?: throw IllegalStateException("unknown session")
        return SessionCipher(store, address).encrypt(plaintext).serialize()
    }

    override fun decrypt(session: SessionHandle, payload: ByteArray): ByteArray {
        val address = sessions[session.id] ?: throw IllegalStateException("unknown session")
        val cipher = SessionCipher(store, address)
        return try {
            cipher.decrypt(PreKeySignalMessage(payload))
        } catch (_: InvalidMessageException) {
            cipher.decrypt(SignalMessage(payload))
        }
    }

    override fun safetyNumber(localIdentity: ByteArray, remoteIdentity: ByteArray): String =
        SafetyNumber.of(localIdentity, remoteIdentity).digits

    /** Device Ed25519 (Tink). Account proofs must use [AccountKey.sign]. */
    override fun sign(message: ByteArray): ByteArray = Ed25519Sign(deviceEd25519.privateKey).sign(message)

    companion object {
        const val DJB_TYPE: Byte = 0x05

        fun create(): LibsignalEngine = LibsignalEngine()

        fun stripDjb(serialized: ByteArray): ByteArray {
            require(serialized.size == 33 && serialized[0] == DJB_TYPE) { "expected 33-byte DJB public key" }
            return serialized.copyOfRange(1, 33)
        }

        fun prefixDjb(raw32: ByteArray): ByteArray {
            require(raw32.size == 32) { "expected 32-byte public key" }
            return byteArrayOf(DJB_TYPE) + raw32
        }

        private fun b64(bytes: ByteArray): String = Base64.encodeToString(bytes, Base64.NO_WRAP)

        private fun b64d(s: String): ByteArray = Base64.decode(s, Base64.DEFAULT)
    }
}

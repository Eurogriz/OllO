package app.ollo.crypto

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream

/**
 * Sealed local history. Bodies are already-decrypted plaintext wrapped with
 * the device key — the server never supplies them. Production Android should
 * eventually park rows in SQLCipher; this codec + TTL + wipe is the contract.
 */
data class LocalMessage(
    val clientId: String,
    val threadId: String,
    val senderId: String,
    val sentAt: Long,
    val status: String,
    val body: ByteArray,
    val expiresAt: Long? = null,
)

class MessageLog(
    private val store: IdentityStore,
    private val wrapKey: ByteArray,
) {
    fun put(message: LocalMessage) {
        store.put(wrapKey, key(message.clientId), LocalMessageCodec.encode(message))
    }

    fun get(clientId: String): LocalMessage? {
        val raw = store.get(wrapKey, key(clientId)) ?: return null
        return LocalMessageCodec.decode(raw)
    }

    fun list(threadId: String): List<LocalMessage> =
        store.keys(PREFIX)
            .mapNotNull { k -> store.get(wrapKey, k)?.let { LocalMessageCodec.decode(it) } }
            .filter { it.threadId == threadId }
            .sortedBy { it.sentAt }

    fun expire(now: Long): Int {
        var n = 0
        for (k in store.keys(PREFIX)) {
            val raw = store.get(wrapKey, k) ?: continue
            val msg = LocalMessageCodec.decode(raw)
            val exp = msg.expiresAt
            if (exp != null && exp <= now) {
                store.remove(k)
                n += 1
            }
        }
        return n
    }

    private fun key(clientId: String): String {
        assertSafeStoreKey(clientId)
        return PREFIX + clientId
    }

    companion object {
        const val PREFIX = "msg."
    }
}

object LocalMessageCodec {
    private val MAGIC = byteArrayOf(0x4F, 0x4C, 0x4D, 0x32) // OLM2

    fun encode(message: LocalMessage): ByteArray {
        val out = ByteArrayOutputStream()
        DataOutputStream(out).use { d ->
            d.write(MAGIC)
            writeUtf(d, message.clientId)
            writeUtf(d, message.threadId)
            writeUtf(d, message.senderId)
            d.writeLong(message.sentAt)
            d.writeLong(message.expiresAt ?: 0L)
            writeUtf(d, message.status)
            d.writeInt(message.body.size)
            d.write(message.body)
        }
        return out.toByteArray()
    }

    fun decode(bytes: ByteArray): LocalMessage {
        if (bytes.size < 8) throw IllegalArgumentException("message too short")
        val d = DataInputStream(ByteArrayInputStream(bytes))
        val mag = ByteArray(4)
        d.readFully(mag)
        if (!mag.contentEquals(MAGIC)) throw IllegalArgumentException("bad message magic")
        val clientId = readUtf(d)
        val threadId = readUtf(d)
        val senderId = readUtf(d)
        val sentAt = d.readLong()
        val exp = d.readLong()
        val status = readUtf(d)
        val n = d.readInt()
        if (n < 0 || n > 8 * 1024 * 1024) throw IllegalArgumentException("message body too large")
        val body = ByteArray(n)
        d.readFully(body)
        return LocalMessage(
            clientId = clientId,
            threadId = threadId,
            senderId = senderId,
            sentAt = sentAt,
            status = status,
            body = body,
            expiresAt = if (exp == 0L) null else exp,
        )
    }

    private fun writeUtf(d: DataOutputStream, s: String) {
        val b = s.toByteArray(Charsets.UTF_8)
        d.writeShort(b.size)
        d.write(b)
    }

    private fun readUtf(d: DataInputStream): String {
        val n = d.readUnsignedShort()
        val b = ByteArray(n)
        d.readFully(b)
        return String(b, Charsets.UTF_8)
    }
}

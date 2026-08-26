package app.ollo.crypto

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream

/**
 * Length-prefixed map used for opaque libsignal records.
 * Magic `OLM1`. Not a ratchet — only a container.
 */
object BlobMap {
    private val MAGIC = byteArrayOf(0x4F, 0x4C, 0x4D, 0x31) // OLM1

    fun encode(map: Map<String, ByteArray>): ByteArray {
        val out = ByteArrayOutputStream()
        DataOutputStream(out).use { d ->
            d.write(MAGIC)
            d.writeInt(map.size)
            for ((k, v) in map) {
                val key = k.toByteArray(Charsets.UTF_8)
                d.writeShort(key.size)
                d.write(key)
                d.writeInt(v.size)
                d.write(v)
            }
        }
        return out.toByteArray()
    }

    fun decode(bytes: ByteArray): LinkedHashMap<String, ByteArray> {
        if (bytes.size < 8) throw IllegalArgumentException("blob map too short")
        val d = DataInputStream(ByteArrayInputStream(bytes))
        val mag = ByteArray(4)
        d.readFully(mag)
        if (!mag.contentEquals(MAGIC)) throw IllegalArgumentException("bad blob map magic")
        val n = d.readInt()
        if (n < 0 || n > 100_000) throw IllegalArgumentException("blob map count")
        val map = LinkedHashMap<String, ByteArray>(n)
        repeat(n) {
            val klen = d.readUnsignedShort()
            val key = ByteArray(klen)
            d.readFully(key)
            val vlen = d.readInt()
            if (vlen < 0 || vlen > 8 * 1024 * 1024) throw IllegalArgumentException("blob value too large")
            val value = ByteArray(vlen)
            d.readFully(value)
            map[String(key, Charsets.UTF_8)] = value
        }
        return map
    }
}

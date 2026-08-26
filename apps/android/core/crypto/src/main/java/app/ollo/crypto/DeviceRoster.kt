package app.ollo.crypto

import java.io.ByteArrayOutputStream
import java.security.MessageDigest

/**
 * Hash of the live device roster. Includes device ids so a restored extra
 * device with the same identity keys is still visible. Must match
 * `packages/crypto/src/safety.ts` `deviceRosterHash`.
 */
object DeviceRoster {
    data class Device(val deviceId: String, val identityX25519: ByteArray)

    enum class Decision { New, Unchanged, Changed }

    fun hash(devices: List<Device>): String {
        val sorted = devices.sortedBy { it.deviceId }
        val out = ByteArrayOutputStream()
        out.write("ollo-roster-v1".toByteArray(Charsets.UTF_8))
        for (d in sorted) {
            out.write(d.deviceId.toByteArray(Charsets.UTF_8))
            out.write(0)
            out.write(d.identityX25519)
            out.write(0)
        }
        val digest = MessageDigest.getInstance("SHA-256").digest(out.toByteArray())
        return digest.joinToString("") { b -> "%02x".format(b.toInt() and 0xff) }
    }

    fun note(previous: String?, next: String): Decision {
        if (previous == null) return Decision.New
        return if (previous == next) Decision.Unchanged else Decision.Changed
    }
}

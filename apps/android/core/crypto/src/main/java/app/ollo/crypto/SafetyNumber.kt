package app.ollo.crypto

import java.security.MessageDigest

/**
 * Safety number matching `packages/crypto/src/safety.ts`.
 * 60 decimal digits from SHA-256 over the sorted identity pair.
 */
object SafetyNumber {
    private val PREFIX_A = "ollo-safety-v1".toByteArray(Charsets.UTF_8)
    private val PREFIX_B = "ollo-safety-v1-b".toByteArray(Charsets.UTF_8)

    data class Result(
        val digits: String,
        val grouped: String,
        val hex: String,
        val qr: String,
    )

    fun of(identityA: ByteArray, identityB: ByteArray): Result {
        val (first, second) = if (compare(identityA, identityB) <= 0) {
            identityA to identityB
        } else {
            identityB to identityA
        }
        val digest = sha256(PREFIX_A + first + second)
        val digest2 = sha256(PREFIX_B + first + second)
        val digits = buildString(60) {
            for (i in 0 until 30) append((digest[i].toInt() and 0xff) % 10)
            for (i in 0 until 30) append((digest2[i].toInt() and 0xff) % 10)
        }
        val hex = digest.joinToString("") { b -> "%02x".format(b.toInt() and 0xff) }
        val grouped = digits.chunked(5).joinToString(" ")
        return Result(digits = digits, grouped = grouped, hex = hex, qr = "ollo:safety:v1:$hex")
    }

    private fun sha256(input: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(input)

    private fun compare(a: ByteArray, b: ByteArray): Int {
        val n = minOf(a.size, b.size)
        for (i in 0 until n) {
            val av = a[i].toInt() and 0xff
            val bv = b[i].toInt() and 0xff
            if (av != bv) return av - bv
        }
        return a.size - b.size
    }
}

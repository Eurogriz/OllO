package app.ollo.crypto

import org.junit.Assert.assertEquals
import org.junit.Test

class SafetyNumberTest {
    @Test
    fun knownAnswerVector() {
        val a = ByteArray(32) { 1 }
        val b = ByteArray(32) { 2 }
        val s = SafetyNumber.of(a, b)
        assertEquals("153665515321528787008757103930069366995789004059450082545955", s.digits)
        assertEquals("f1d7e960a6cd69014103fcdd5ff23a894e93c8008057e107ab6e6795df5a9003", s.hex)
        assertEquals(s.digits, SafetyNumber.of(b, a).digits)
        assertEquals(60, s.digits.length)
    }
}

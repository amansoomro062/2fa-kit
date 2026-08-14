package com.acme.authenticator

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.math.pow

/**
 * Hand-rolled TOTP (RFC 6238) / HOTP (RFC 4226) core, interoperable with
 * 2fa-kit and every other standard authenticator. Defaults match the
 * ecosystem: SHA-1, 6 digits, 30 second period.
 */
object Totp {

    data class Params(
        val algorithm: String = "SHA1",
        val digits: Int = 6,
        val period: Int = 30,
    )

    /** Current code for [secret]. Accepts the secret in any common spelling
     *  (lowercase, unpadded, with spaces). */
    fun generate(secret: String, params: Params = Params(), timeMillis: Long = System.currentTimeMillis()): String {
        val counter = timeMillis / 1000L / params.period
        return hotp(secret, counter, params)
    }

    /** Seconds until the current code expires. */
    fun remaining(period: Int = 30, timeMillis: Long = System.currentTimeMillis()): Int {
        return (period - (timeMillis / 1000L) % period).toInt()
    }

    /** RFC 4226 HOTP. [counter] is a full 8-byte big-endian value, so
     *  counters above 2^31 work correctly (Long, no 32-bit truncation). */
    fun hotp(secret: String, counter: Long, params: Params = Params()): String {
        val message = ByteArray(8)
        var c = counter
        for (i in 7 downTo 0) {
            message[i] = (c and 0xff).toByte()
            c = c shr 8
        }

        val mac = Mac.getInstance("Hmac${normalizeAlgorithm(params.algorithm)}")
        mac.init(SecretKeySpec(base32Decode(secret), mac.algorithm))
        val hash = mac.doFinal(message)

        // Dynamic truncation (RFC 4226 section 5.4).
        val offset = hash[hash.size - 1].toInt() and 0x0f
        val binary = ((hash[offset].toInt() and 0x7f) shl 24) or
            ((hash[offset + 1].toInt() and 0xff) shl 16) or
            ((hash[offset + 2].toInt() and 0xff) shl 8) or
            (hash[offset + 3].toInt() and 0xff)

        val modulus = 10.0.pow(params.digits).toLong()
        return (binary.toLong() % modulus).toString().padStart(params.digits, '0')
    }

    /** Map otpauth algorithm spellings (SHA1, SHA-1, SHA256, ...) onto the
     *  JCA Mac names. */
    private fun normalizeAlgorithm(algorithm: String): String {
        return when (algorithm.uppercase().replace("-", "")) {
            "SHA1" -> "SHA1"
            "SHA256" -> "SHA256"
            "SHA512" -> "SHA512"
            else -> throw IllegalArgumentException("Unsupported algorithm: $algorithm")
        }
    }

    private val BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    /** RFC 4648 base32 decode. Tolerates lowercase input, missing padding,
     *  and embedded spaces, the same way 2fa-kit does. */
    fun base32Decode(input: String): ByteArray {
        val cleaned = input.uppercase().replace(" ", "").trimEnd('=')
        val out = ArrayList<Byte>(cleaned.length * 5 / 8)
        var buffer = 0
        var bits = 0
        for (ch in cleaned) {
            val value = BASE32_ALPHABET.indexOf(ch)
            if (value < 0) throw IllegalArgumentException("Invalid base32 character: $ch")
            buffer = (buffer shl 5) or value
            bits += 5
            if (bits >= 8) {
                out.add(((buffer shr (bits - 8)) and 0xff).toByte())
                bits -= 8
            }
        }
        return out.toByteArray()
    }
}

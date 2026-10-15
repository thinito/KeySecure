package com.example.KeySecure.crypto

import com.example.KeySecure.data.SecurityPolicy
import java.security.SecureRandom
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

object KeyDerivation {

    private val random = SecureRandom()

    fun randomBytes(size: Int): ByteArray =
        ByteArray(size).also { random.nextBytes(it) }

    /**
     * Deriva uma chave AES-256 via PBKDF2-HMAC-SHA256.
     * Sempre limpa o PBEKeySpec após o uso.
     */
    fun derive(
        password: CharArray,
        salt: ByteArray,
        iterations: Int = SecurityPolicy.PBKDF2_ITERATIONS
    ): SecretKey {
        val spec = PBEKeySpec(password, salt, iterations, 256)
        try {
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            val bytes = factory.generateSecret(spec).encoded
            return SecretKeySpec(bytes, "AES").also {
                // Zera a cópia intermediária
                bytes.fill(0)
            }
        } finally {
            spec.clearPassword()
        }
    }
}
package com.example.KeySecure.crypto

import com.example.KeySecure.data.SecurityPolicy
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

object Crypto {

    private val random = SecureRandom()

    fun randomBytes(size: Int): ByteArray =
        ByteArray(size).also { random.nextBytes(it) }

    /**
     * Deriva uma chave AES de 256 bits via PBKDF2-HMAC-SHA256.
     * @param password em CharArray (permite limpeza após uso).
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
            return SecretKeySpec(bytes, "AES").also { bytes.fill(0) }
        } finally {
            spec.clearPassword()
        }
    }

    /** Cifra com AES-256-GCM. Retorna IV || ciphertext||tag. */
    fun encrypt(key: SecretKey, plaintext: ByteArray): ByteArray {
        val iv = randomBytes(SecurityPolicy.IV_LENGTH_BYTES)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.ENCRYPT_MODE, key,
            GCMParameterSpec(SecurityPolicy.GCM_TAG_BITS, iv)
        )
        return iv + cipher.doFinal(plaintext)
    }

    /** Decifra IV || ciphertext||tag. */
    fun decrypt(key: SecretKey, blob: ByteArray): ByteArray {
        require(blob.size > SecurityPolicy.IV_LENGTH_BYTES) { "Blob inválido" }
        val iv = blob.copyOfRange(0, SecurityPolicy.IV_LENGTH_BYTES)
        val ct = blob.copyOfRange(SecurityPolicy.IV_LENGTH_BYTES, blob.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE, key,
            GCMParameterSpec(SecurityPolicy.GCM_TAG_BITS, iv)
        )
        return cipher.doFinal(ct)
    }
}
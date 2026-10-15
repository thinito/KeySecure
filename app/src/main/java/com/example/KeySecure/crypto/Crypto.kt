package com.example.KeySecure.crypto

import com.example.KeySecure.data.SecurityPolicy
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Criptografia central.
 * - AES-256-GCM com AAD opcional (item 10).
 * - PBKDF2-HMAC-SHA256 (item 13: chame via Dispatchers.Default).
 * - Sem "falsa limpeza" de arrays .encoded (item 8).
 */
object Crypto {

    private val random = SecureRandom()

    fun randomBytes(size: Int): ByteArray =
        ByteArray(size).also { random.nextBytes(it) }

    fun derive(
        password: CharArray,
        salt: ByteArray,
        iterations: Int = SecurityPolicy.PBKDF2_ITERATIONS
    ): SecretKey {
        val spec = PBEKeySpec(password, salt, iterations, 256)
        return try {
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            SecretKeySpec(factory.generateSecret(spec).encoded, "AES")
        } finally {
            spec.clearPassword()
        }
    }

    /** Cifra com AAD opcional. Retorna IV || ciphertext||tag. */
    fun encrypt(key: SecretKey, plaintext: ByteArray, aad: ByteArray? = null): ByteArray {
        val iv = randomBytes(SecurityPolicy.IV_LENGTH_BYTES)
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(SecurityPolicy.GCM_TAG_BITS, iv))
        if (aad != null) c.updateAAD(aad)
        return iv + c.doFinal(plaintext)
    }

    fun decrypt(key: SecretKey, blob: ByteArray, aad: ByteArray? = null): ByteArray {
        require(blob.size > SecurityPolicy.IV_LENGTH_BYTES) { "Blob inválido" }
        val iv = blob.copyOfRange(0, SecurityPolicy.IV_LENGTH_BYTES)
        val ct = blob.copyOfRange(SecurityPolicy.IV_LENGTH_BYTES, blob.size)
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(SecurityPolicy.GCM_TAG_BITS, iv))
        if (aad != null) c.updateAAD(aad)
        return c.doFinal(ct)
    }
}
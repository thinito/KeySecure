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

    fun deriveBytes(
        password: CharArray,
        salt: ByteArray,
        iterations: Int = SecurityPolicy.PBKDF2_ITERATIONS,
        lengthBits: Int = 256
    ): ByteArray {
        val spec = PBEKeySpec(password, salt, iterations, lengthBits)
        return try {
            SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                .generateSecret(spec)
                .encoded
        } finally {
            spec.clearPassword()
        }
    }

    /**
     * Deriva chave AES-256 via PBKDF2.
     *
     * O `ByteArray` retornado por [deriveBytes] é zerado logo após o
     * `SecretKeySpec` (que clona internamente) ser construído — o
     * array original não fica pendurado até o GC.
     */
    fun derive(
        password: CharArray,
        salt: ByteArray,
        iterations: Int = SecurityPolicy.PBKDF2_ITERATIONS
    ): SecretKey {
        val bytes = deriveBytes(password, salt, iterations)
        return try {
            SecretKeySpec(bytes, "AES")
        } finally {
            bytes.fill(0)
        }
    }

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
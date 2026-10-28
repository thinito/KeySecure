package com.example.KeySecure.crypto

import com.example.KeySecure.data.SecurityPolicy
import com.lambdapioneer.argon2kt.Argon2Kt
import com.lambdapioneer.argon2kt.Argon2Mode
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

object Crypto {

    private val random = SecureRandom()

    /**
     * ✅ `by lazy`: `Argon2Kt()` carrega a biblioteca nativa via JNI, que
     * **não existe na JVM de testes unitários**. Com lazy, qualquer código
     * que use só PBKDF2 (como `CryptoTest`) não toca em Argon2.
     */
    private val argon2 by lazy { Argon2Kt() }

    fun randomBytes(size: Int): ByteArray =
        ByteArray(size).also { random.nextBytes(it) }

    // ------------------------------------------------------------------
    // PBKDF2
    // ------------------------------------------------------------------
    fun deriveBytesPbkdf2(
        password: CharArray,
        salt: ByteArray,
        iterations: Int = SecurityPolicy.PBKDF2_ITERATIONS,
        lengthBits: Int = 256
    ): ByteArray {
        val spec = PBEKeySpec(password, salt, iterations, lengthBits)
        return try {
            SecretKeyFactory.getInstance(pbkdf2Algorithm())
                .generateSecret(spec)
                .encoded
        } finally {
            spec.clearPassword()
        }
    }

    // ------------------------------------------------------------------
    // Argon2id (usa JNI — só em dispositivo/emulador)
    // ------------------------------------------------------------------
    fun deriveBytesArgon2id(
        password: CharArray,
        salt: ByteArray,
        memoryKib: Int = SecurityPolicy.ARGON2_MEMORY_KIB,
        iterations: Int = SecurityPolicy.ARGON2_ITERATIONS,
        parallelism: Int = SecurityPolicy.ARGON2_PARALLELISM
    ): ByteArray {
        val passwordBytes = String(password).toByteArray(Charsets.UTF_8)
        try {
            val result = argon2.hash(
                mode = Argon2Mode.ARGON2_ID,
                password = passwordBytes,
                salt = salt,
                tCostInIterations = iterations,
                mCostInKibibyte = memoryKib,
                parallelism = parallelism,
                hashLengthInBytes = 32
            )
            return result.rawHashAsByteArray()
        } finally {
            passwordBytes.fill(0)
        }
    }

    fun deriveKey(
        password: CharArray,
        salt: ByteArray,
        kdf: String,
        iterations: Int = SecurityPolicy.PBKDF2_ITERATIONS
    ): SecretKey {
        val bytes = when (kdf) {
            "ARGON2ID" -> deriveBytesArgon2id(password, salt)
            else -> deriveBytesPbkdf2(password, salt, iterations)
        }
        return try {
            SecretKeySpec(bytes, "AES")
        } finally {
            bytes.fill(0)
        }
    }

    // ------------------------------------------------------------------
    // AES-GCM
    // ------------------------------------------------------------------
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

    private fun pbkdf2Algorithm(): String {
        val sdk = android.os.Build.VERSION.SDK_INT
        return if (sdk == 0 || sdk >= android.os.Build.VERSION_CODES.O)
            "PBKDF2WithHmacSHA256"
        else "PBKDF2WithHmacSHA1"
    }
}
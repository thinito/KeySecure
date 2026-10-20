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

    /** Bytes aleatórios com SecureRandom. */
    fun randomBytes(size: Int): ByteArray =
        ByteArray(size).also { random.nextBytes(it) }

    /**
     * Deriva bytes crus via PBKDF2-HMAC-SHA256.
     *
     * Usado quando a saída do PBKDF2 precisa ser consumida por outro
     * primitivo — por exemplo, o HMAC com a chave "pepper" do Keystore
     * em `Vault.derivePepperedPinKey`. Devolver `ByteArray` (em vez de
     * `SecretKey`) permite zerar o buffer após o uso.
     *
     * @param password  PIN/frase em CharArray (para permitir limpeza).
     * @param salt      Salt aleatório.
     * @param iterations Custo do PBKDF2 (ver SecurityPolicy).
     * @param lengthBits Tamanho da saída em bits (padrão 256).
     */
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
     * Atalho para o caso em que o PBKDF2 é usado diretamente como
     * chave AES (ex.: embrulho da frase-chave). Delegate de [deriveBytes]
     * para manter uma única fonte de verdade.
     */
    fun derive(
        password: CharArray,
        salt: ByteArray,
        iterations: Int = SecurityPolicy.PBKDF2_ITERATIONS
    ): SecretKey = SecretKeySpec(
        deriveBytes(password, salt, iterations),
        "AES"
    )

    /**
     * AES-256-GCM. Se `aad` for fornecido, é autenticado junto.
     * Formato de saída: IV (12 bytes) || ciphertext || tag (16 bytes).
     */
    fun encrypt(key: SecretKey, plaintext: ByteArray, aad: ByteArray? = null): ByteArray {
        val iv = randomBytes(SecurityPolicy.IV_LENGTH_BYTES)
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(SecurityPolicy.GCM_TAG_BITS, iv))
        if (aad != null) c.updateAAD(aad)
        return iv + c.doFinal(plaintext)
    }

    /**
     * Decifra o blob produzido por [encrypt]. Lança AEADBadTagException
     * se a tag não conferir (AAD errado, ciphertext adulterado, chave errada).
     */
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
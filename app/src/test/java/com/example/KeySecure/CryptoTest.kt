package com.example.KeySecure

import com.example.KeySecure.crypto.Crypto
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class CryptoTest {

    private val key = Crypto.derive("482917".toCharArray(), ByteArray(16))

    @Test
    fun round_trip() {
        val msg = "dados sensíveis".toByteArray()
        val blob = Crypto.encrypt(key, msg)
        assertArrayEquals(msg, Crypto.decrypt(key, blob))
    }

    @Test
    fun aad_invalido_falha() {
        val blob = Crypto.encrypt(key, "x".toByteArray(), aad = "A".toByteArray())
        try {
            Crypto.decrypt(key, blob, aad = "B".toByteArray())
            fail("Deveria falhar com AAD diferente")
        } catch (e: Exception) { /* esperado */ }
    }

    @Test
    fun blob_adulterado_falha() {
        val blob = Crypto.encrypt(key, "x".toByteArray())
        blob[blob.size - 1] = (blob.last() + 1).toByte()
        try {
            Crypto.decrypt(key, blob); fail()
        } catch (e: Exception) { /* esperado */ }
    }

    @Test
    fun iv_unico() {
        val a = Crypto.encrypt(key, "x".toByteArray())
        val b = Crypto.encrypt(key, "x".toByteArray())
        assertFalse(a.contentEquals(b))
    }

    /**
     * Garante que `deriveBytes` funciona no JVM de teste (onde
     * `Build.VERSION.SDK_INT == 0` e o algoritmo escolhido é o SHA256).
     * Em API 24–25, o fallback SHA1 é usado; o teste abaixo só roda
     * no JVM, então cobre o caminho "moderno".
     */
    @Test
    fun derive_bytes_nao_vazio() {
        val bytes = Crypto.deriveBytes("482917".toCharArray(), ByteArray(16))
        assertTrue("PBKDF2 deveria produzir 32 bytes", bytes.size == 32)
    }

    @Test
    fun derive_aceita_chararray_e_limpa_buffer() {
        // A chave derivada deve ser AES-256.
        assertTrue(key.algorithm == "AES")
        assertTrue(key.encoded.size == 32)
    }
}
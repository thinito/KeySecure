package com.example.KeySecure

import com.example.KeySecure.crypto.Crypto
import com.example.KeySecure.data.SecurityPolicy
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Testes JVM de PBKDF2 + AES-GCM.
 * Argon2id não roda em JVM (JNI) — testes desse caminho ficam em androidTest/.
 */
class CryptoTest {

    private val key = Crypto.deriveKey(
        password = "482917".toCharArray(),
        salt = ByteArray(16),
        kdf = "PBKDF2"
    )

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
            Crypto.decrypt(key, blob)
            fail("Deveria falhar com blob adulterado")
        } catch (e: Exception) { /* esperado */ }
    }

    @Test
    fun iv_unico() {
        val a = Crypto.encrypt(key, "x".toByteArray())
        val b = Crypto.encrypt(key, "x".toByteArray())
        assertFalse(a.contentEquals(b))
    }

    @Test
    fun pbkdf2_deriva_bytes_validos() {
        val bytes = Crypto.deriveBytesPbkdf2("482917".toCharArray(), ByteArray(16))
        assertNotNull(bytes)
        assertTrue("PBKDF2 deve produzir 32 bytes", bytes.size == 32)
    }

    @Test
    fun pbkdf2_e_deterministico() {
        val a = Crypto.deriveBytesPbkdf2("482917".toCharArray(), ByteArray(16))
        val b = Crypto.deriveBytesPbkdf2("482917".toCharArray(), ByteArray(16))
        assertArrayEquals(a, b)
    }

    @Test
    fun pbkdf2_salt_diferente_produz_chave_diferente() {
        val a = Crypto.deriveBytesPbkdf2("482917".toCharArray(), ByteArray(16) { 0 })
        val b = Crypto.deriveBytesPbkdf2("482917".toCharArray(), ByteArray(16) { 1 })
        assertFalse(a.contentEquals(b))
    }

    @Test
    fun derive_key_pbkdf2_gera_chave_aes_256() {
        assertTrue(key.algorithm == "AES")
        assertTrue(key.encoded.size == 32)
    }

    @Test
    fun valida_iteracoes_do_pbkdf2() {
        assertFalse(SecurityPolicy.validateIterations(1000))
        assertFalse(SecurityPolicy.validateIterations(10_000_000))
        assertTrue(SecurityPolicy.validateIterations(SecurityPolicy.PBKDF2_ITERATIONS))
    }
}
package com.example.KeySecure

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.example.KeySecure.crypto.Crypto
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Testes instrumentados do Argon2id.
 *
 * Rodam em dispositivo/emulador (o `argon2kt` usa JNI, indisponível na JVM).
 *
 * Executar:
 *   ./gradlew connectedAndroidTest
 */
@RunWith(AndroidJUnit4::class)
class Argon2Test {

    @Test
    fun argon2_deriva_32_bytes() {
        val bytes = Crypto.deriveBytesArgon2id(
            password = "frase bem longa!".toCharArray(),
            salt = ByteArray(16)
        )
        assertEquals(32, bytes.size)
    }

    @Test
    fun argon2_e_deterministico() {
        val a = Crypto.deriveBytesArgon2id("frase".toCharArray(), ByteArray(16))
        val b = Crypto.deriveBytesArgon2id("frase".toCharArray(), ByteArray(16))
        assertTrue(a.contentEquals(b))
    }

    @Test
    fun argon2_salt_diferente_gera_chave_diferente() {
        val a = Crypto.deriveBytesArgon2id("frase".toCharArray(), ByteArray(16) { 0 })
        val b = Crypto.deriveBytesArgon2id("frase".toCharArray(), ByteArray(16) { 1 })
        assertFalse(a.contentEquals(b))
    }
}
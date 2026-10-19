package com.example.KeySecure

import com.example.KeySecure.crypto.Crypto
import org.junit.Assert.*
import org.junit.Test

class CryptoTest {

    private val key = Crypto.derive("123456".toCharArray(), ByteArray(16))

    @Test fun round_trip() {
        val msg = "dados sensíveis".toByteArray()
        val blob = Crypto.encrypt(key, msg)
        assertArrayEquals(msg, Crypto.decrypt(key, blob))
    }

    @Test fun aad_invalido_falha() {
        val blob = Crypto.encrypt(key, "x".toByteArray(), aad = "A".toByteArray())
        try {
            Crypto.decrypt(key, blob, aad = "B".toByteArray())
            fail("Deveria falhar com AAD diferente")
        } catch (e: Exception) { /* esperado */ }
    }

    @Test fun blob_adulterado_falha() {
        val blob = Crypto.encrypt(key, "x".toByteArray())
        blob[blob.size - 1] = (blob.last() + 1).toByte()
        try {
            Crypto.decrypt(key, blob); fail()
        } catch (e: Exception) { /* esperado */ }
    }

    @Test fun iv_unico() {
        val a = Crypto.encrypt(key, "x".toByteArray())
        val b = Crypto.encrypt(key, "x".toByteArray())
        assertFalse(a.contentEquals(b))
    }
}
package com.example.KeySecure

import com.example.KeySecure.data.SecurityPolicy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SecurityPolicyTest {

    // PIN "482917": 6 dígitos ASCII, sem repetição, sem sequência crescente/decrescente.
    // Use este como padrão em todos os testes.
    private val validPin = "482917"

    @Test
    fun pin_valido() {
        assertTrue("PIN '$validPin' deveria ser válido",
            SecurityPolicy.isStrongPin(validPin)
        )
    }

    @Test
    fun pin_curto_invalido() {
        assertFalse(SecurityPolicy.isStrongPin("12345"))
    }

    @Test
    fun pin_longo_invalido() {
        assertFalse(SecurityPolicy.isStrongPin("1234567890123"))
    }

    @Test
    fun pin_rejeita_nao_ascii() {
        assertFalse(SecurityPolicy.isStrongPin("١٢٣٤٥٦"))
    }

    @Test
    fun pin_rejeita_triviais() {
        assertFalse(SecurityPolicy.isStrongPin("000000"))
        assertFalse(SecurityPolicy.isStrongPin("111111"))
        assertFalse(SecurityPolicy.isStrongPin("123456"))
        assertFalse(SecurityPolicy.isStrongPin("654321"))
    }

    @Test
    fun frase_normaliza_nfkc() {
        val a = "café com leite"
        val b = "cafe\u0301 com leite"
        assertEquals(
            SecurityPolicy.normalizePassphrase(a),
            SecurityPolicy.normalizePassphrase(b)
        )
    }

    @Test
    fun frase_rejeita_fraca() {
        assertFalse(SecurityPolicy.isStrongPassphrase("aaaaaaaaaaaa"))
        assertFalse(SecurityPolicy.isStrongPassphrase("password"))
        assertTrue(SecurityPolicy.isStrongPassphrase("minha frase boa 2024"))
    }

    @Test
    fun valida_iteracoes() {
        assertFalse(SecurityPolicy.validateIterations(1000))
        assertFalse(SecurityPolicy.validateIterations(10_000_000))
        assertTrue(SecurityPolicy.validateIterations(600_000))
    }
}
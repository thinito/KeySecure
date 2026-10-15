package com.example.KeySecure

import com.example.KeySecure.data.SecurityPolicy
import org.junit.Assert.*
import org.junit.Test

class SecurityPolicyTest {

    @Test fun pin_valido_6_a_12() {
        assertTrue(SecurityPolicy.isValidPin("123456"))
        assertTrue(SecurityPolicy.isValidPin("8529637410"))
        assertFalse(SecurityPolicy.isValidPin("12345"))
        assertFalse(SecurityPolicy.isValidPin("1234567890123")) // 13 dígitos
    }

    @Test fun pin_rejeita_nao_ascii() {
        // Dígitos árabes-indianos
        assertFalse(SecurityPolicy.isValidPin("١٢٣٤٥٦"))
    }

    @Test fun pin_rejeita_triviais() {
        assertFalse(SecurityPolicy.isValidPin("000000"))
        assertFalse(SecurityPolicy.isValidPin("123456"))
        assertFalse(SecurityPolicy.isValidPin("654321"))
    }

    @Test fun frase_normaliza_nfkc() {
        val a = "café com leite"
        val b = "cafe\u0301 com leite" // combinante
        assertEquals(SecurityPolicy.normalizePassphrase(a),
                     SecurityPolicy.normalizePassphrase(b))
    }

    @Test fun frase_rejeita_fraca() {
        assertFalse(SecurityPolicy.isValidPassphrase("aaaaaaaaaaaa"))
        assertFalse(SecurityPolicy.isValidPassphrase("password"))
        assertTrue(SecurityPolicy.isValidPassphrase("minha frase boa 2024"))
    }

    @Test fun valida_iteracoes() {
        assertFalse(SecurityPolicy.validateIterations(1000))
        assertFalse(SecurityPolicy.validateIterations(10_000_000))
        assertTrue(SecurityPolicy.validateIterations(600_000))
    }
}
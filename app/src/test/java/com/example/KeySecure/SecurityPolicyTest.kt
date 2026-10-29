package com.example.KeySecure

import com.example.KeySecure.data.SecurityPolicy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SecurityPolicyTest {

    // PIN de 8 dígitos, ASCII, sem repetição, sem sequência.
    // 48291736 → não é crescente (8→2 quebra), não é decrescente (4→8 quebra),
    // não tem todos iguais. Aceito por isStrongPin com MIN_PIN_LENGTH = 8.
    private val validPin = "48291736"

    @Test
    fun pin_valido() {
        assertTrue(
            "PIN '$validPin' deveria ser válido (8 dígitos, não trivial)",
            SecurityPolicy.isStrongPin(validPin)
        )
    }

    @Test
    fun pin_curto_invalido() {
        assertFalse(SecurityPolicy.isStrongPin("482917"))     // 6 dígitos
        assertFalse(SecurityPolicy.isStrongPin("4829173"))    // 7 dígitos
    }

    @Test
    fun pin_longo_invalido() {
        assertFalse(SecurityPolicy.isStrongPin("4829173654321")) // 13 dígitos
    }

    @Test
    fun pin_rejeita_nao_ascii() {
        assertFalse(SecurityPolicy.isStrongPin("١٢٣٤٥٦٧٨"))
    }

    @Test
    fun pin_rejeita_triviais() {
        // PINs de 8 dígitos triviais
        assertFalse("00000000 é repetitivo", SecurityPolicy.isStrongPin("00000000"))
        assertFalse("11111111 é repetitivo", SecurityPolicy.isStrongPin("11111111"))
        assertFalse("12345678 é crescente", SecurityPolicy.isStrongPin("12345678"))
        assertFalse("87654321 é decrescente", SecurityPolicy.isStrongPin("87654321"))
    }

    @Test
    fun pin_bem_formado_aceita_6_digitos_historicos() {
        // isWellFormedPin usa HISTORICAL_MIN_PIN_LENGTH = 6 — PINs antigos abrem.
        assertTrue(SecurityPolicy.isWellFormedPin("482917"))
        assertTrue(SecurityPolicy.isWellFormedPin("48291736"))
        assertFalse(SecurityPolicy.isWellFormedPin("48291"))     // 5 dígitos
        assertFalse(SecurityPolicy.isWellFormedPin("4829173654321")) // 13 dígitos
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
        assertFalse(SecurityPolicy.isStrongPassphrase("Senha1234568"))   // zxcvbn < 60 bits
        assertTrue(
            SecurityPolicy.isStrongPassphrase(
                "correct horse battery staple zinc guitar violet"
            )
        )
    }

    @Test
    fun valida_iteracoes() {
        assertFalse(SecurityPolicy.validateIterations(1000))
        assertFalse(SecurityPolicy.validateIterations(10_000_000))
        assertTrue(SecurityPolicy.validateIterations(SecurityPolicy.PBKDF2_ITERATIONS))
    }
}
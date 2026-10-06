package com.example.KeySecure

import com.example.KeySecure.data.SecurityPolicy
import org.junit.Assert.*
import org.junit.Test

class SecurityPolicyTest {
    @Test fun pin_curto_invalido() = assertFalse(SecurityPolicy.isValidPin("12345"))
    @Test fun pin_valido() = assertTrue(SecurityPolicy.isValidPin("123456"))
    @Test fun pin_com_letra_invalido() = assertFalse(SecurityPolicy.isValidPin("12a456"))
    @Test fun frase_curta_invalida() = assertFalse(SecurityPolicy.isValidPassphrase("curta"))
    @Test fun frase_valida() =
        assertTrue(SecurityPolicy.isValidPassphrase("minha frase longa"))
}
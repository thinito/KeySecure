package com.example.KeySecure

import com.example.KeySecure.data.SecurityPolicy
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class VaultMigrationTest {
    @get:Rule val tmp = TemporaryFolder()

    @Test fun cria_e_desbloqueia() {
        val f = tmp.newFile("vault.json")
        val v = Vault(f)
        v.create("123456".toCharArray(), "frase bem longa!".toCharArray())
        v.lock()

        val v2 = Vault(f)
        assertTrue(v2.unlockPin("123456".toCharArray()))
    }

    @Test fun pin_errado_falha() {
        val f = tmp.newFile("vault.json")
        Vault(f).create("123456".toCharArray(), "frase bem longa!".toCharArray())

        val v2 = Vault(f)
        assertFalse(v2.unlockPin("999999".toCharArray()))
    }
}
package com.example.KeySecure

import com.example.KeySecure.crypto.KeystoreManager
import com.example.KeySecure.data.VaultEntry
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * Usa KeystoreManager fake (não chama Android Keystore real).
 */
class FakeKeystore : KeystoreManager() {
    override fun hasKey(): Boolean = false
    override fun createKey() { /* no-op */ }
    override fun getKey() = throw UnsupportedOperationException()
    override fun deleteKey() { /* no-op */ }
}

class VaultMigrationTest {

    @get:Rule val tmp = TemporaryFolder()

    private fun newVault() = Vault(tmp.newFile("vault.json").also { it.delete() }, FakeKeystore())

    @Test fun cria_e_desbloqueia_com_pin() {
        val v = newVault()
        assertTrue(v.create("123456".toCharArray(), "frase bem longa!".toCharArray())
            is UnlockResult.Success)
        v.lock()
        val v2 = newVaultFrom(v)
        assertTrue(v2.unlockPin("123456".toCharArray()) is UnlockResult.Success)
    }

    @Test fun pin_errado_falha() {
        val v = newVault()
        v.create("123456".toCharArray(), "frase bem longa!".toCharArray())
        v.lock()
        assertTrue(v.unlockPin("999999".toCharArray()) is UnlockResult.WrongCredential)
    }

    @Test fun create_recusa_duplicado() {
        val v = newVault()
        v.create("123456".toCharArray(), "frase bem longa!".toCharArray())
        assertTrue(v.create("654321".toCharArray(), "outra frase bem longa!".toCharArray())
            is UnlockResult.Failure)
    }

    @Test fun entradas_persistidas_cifradas() {
        val v = newVault()
        v.create("123456".toCharArray(), "frase bem longa!".toCharArray())
        v.addEntry(VaultEntry("GitHub", "user", "senhaSecreta"))
        v.lock()
        val raw = tmp.root.listFiles()!!.first { it.name == "vault.json" }.readText()
        assertFalse("Senha não deve aparecer em claro no vault.json",
            raw.contains("senhaSecreta"))
    }

    private fun newVaultFrom(v: Vault): Vault {
        // Reutiliza o mesmo arquivo
        val f = tmp.root.listFiles()!!.first { it.name == "vault.json" }
        return Vault(f, FakeKeystore())
    }
}
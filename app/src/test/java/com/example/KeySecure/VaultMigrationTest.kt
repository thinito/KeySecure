package com.example.KeySecure

import com.example.KeySecure.crypto.IKeystore
import com.example.KeySecure.data.VaultEntry
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import javax.crypto.SecretKey

class FakeKeystore : IKeystore {
    override fun hasKey(): Boolean = false
    override fun createKey() { /* no-op */ }
    override fun getKey(): SecretKey =
        throw UnsupportedOperationException("FakeKeystore não fornece chave real")
    override fun deleteKey() { /* no-op */ }
}

class VaultMigrationTest {

    @get:Rule
    val tmp = TemporaryFolder()

    // PIN "482917": válido segundo SecurityPolicy.
    private val validPin = "482917"

    // Frase com 2+ classes de caracteres e >= 12 chars.
    private val validPhrase = "minha frase boa 2024"

    private fun newVault(): Vault {
        val file = File(tmp.root, "vault.json")
        if (file.exists()) file.delete()
        return Vault(file, FakeKeystore())
    }

    private fun vaultFromSameFile(): Vault =
        Vault(File(tmp.root, "vault.json"), FakeKeystore())

    @Test
    fun cria_e_desbloqueia_com_pin() {
        val v = newVault()
        val created = v.create(validPin.toCharArray(), validPhrase.toCharArray())
        assertTrue("create deveria ter sucesso, mas foi $created",
            created is UnlockResult.Success)

        v.lock()

        val v2 = vaultFromSameFile()
        val unlocked = v2.unlockPin(validPin.toCharArray())
        assertTrue("unlockPin deveria ter sucesso, mas foi $unlocked",
            unlocked is UnlockResult.Success)
    }

    @Test
    fun pin_errado_falha() {
        val v = newVault()
        val created = v.create(validPin.toCharArray(), validPhrase.toCharArray())
        assertTrue("pré-condição: create falhou ($created)",
            created is UnlockResult.Success)

        v.lock()

        val result = v.unlockPin("999999".toCharArray())
        assertTrue("esperado WrongCredential, veio $result",
            result is UnlockResult.WrongCredential)
    }

    @Test
    fun create_recusa_duplicado() {
        val v = newVault()
        v.create(validPin.toCharArray(), validPhrase.toCharArray())

        val second = v.create(
            "135790".toCharArray(),
            "outra frase boa 2024!".toCharArray()
        )
        assertTrue("esperado Failure, veio $second",
            second is UnlockResult.Failure)
    }

    @Test
    fun entradas_persistidas_cifradas() {
        val v = newVault()
        val created = v.create(validPin.toCharArray(), validPhrase.toCharArray())
        assertTrue("pré-condição: create falhou ($created)",
            created is UnlockResult.Success)

        v.addEntry(VaultEntry("GitHub", "user", "senhaSecreta"))
        v.lock()

        val raw = File(tmp.root, "vault.json").readText()
        assertFalse(
            "Senha não deve aparecer em claro no vault.json",
            raw.contains("senhaSecreta")
        )
    }
}
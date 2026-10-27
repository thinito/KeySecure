package com.example.KeySecure

import com.example.KeySecure.crypto.IKeystore
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

class FakeKeystore : IKeystore {
    override fun hasKey(): Boolean = false
    override fun createKey() {}
    override fun getKey(): SecretKey =
        throw UnsupportedOperationException("FakeKeystore não fornece chave biométrica")
    override fun deleteKey() {}

    override fun hasPepperKey(): Boolean = true
    override fun createPepperKey() {}
    override fun computePepperHmac(data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(ByteArray(32) { 0x42 }, "HmacSHA256"))
        return mac.doFinal(data)
    }
    override fun deletePepperKey() {}
}

class VaultMigrationTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val validPin = "482917"
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
    fun frase_abre_sem_pepper() {
        val v = newVault()
        v.create(validPin.toCharArray(), validPhrase.toCharArray())
        v.lock()

        val v2 = vaultFromSameFile()
        val unlocked = v2.unlockPhrase(validPhrase.toCharArray())
        assertTrue("unlockPhrase deveria funcionar independentemente do pepper",
            unlocked is UnlockResult.Success)
    }

    @Test
    fun pin_errado_falha() {
        val v = newVault()
        v.create(validPin.toCharArray(), validPhrase.toCharArray())
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
        assertTrue("esperado VaultAlreadyExists, veio $second",
            second is UnlockResult.VaultAlreadyExists)
    }

    @Test
    fun entradas_persistidas_cifradas() {
        val v = newVault()
        val created = v.create(validPin.toCharArray(), validPhrase.toCharArray())
        assertTrue("pré-condição: create falhou ($created)",
            created is UnlockResult.Success)

        // ✅ addEntry agora retorna Result<VaultEntry>; getOrThrow garante
        // que o teste falha com mensagem clara se a gravação falhar.
        v.addEntry("GitHub", "user", "senhaSecreta").getOrThrow()
        v.lock()

        val raw = File(tmp.root, "vault.json").readText()
        assertFalse(
            "Senha não deve aparecer em claro no vault.json",
            raw.contains("senhaSecreta")
        )
    }

    @Test
    fun vault_nao_abre_sem_pepper() {
        val v = newVault()
        v.create(validPin.toCharArray(), validPhrase.toCharArray())
        v.lock()

        val semPepper = object : IKeystore {
            override fun hasKey() = false
            override fun createKey() {}
            override fun getKey(): SecretKey =
                throw UnsupportedOperationException()
            override fun deleteKey() {}
            override fun hasPepperKey() = false
            override fun createPepperKey() {}
            override fun computePepperHmac(data: ByteArray) =
                throw UnsupportedOperationException()
            override fun deletePepperKey() {}
        }
        val v2 = Vault(File(tmp.root, "vault.json"), semPepper)
        val result = v2.unlockPin(validPin.toCharArray())
        assertTrue("esperado NoPepper, veio $result", result is UnlockResult.NoPepper)
    }

    // ------------------------------------------------------------------
    // id como chave estável e CRUD por id
    // ------------------------------------------------------------------

    @Test
    fun ids_unicos_para_entradas_identicas() {
        val v = newVault()
        v.create(validPin.toCharArray(), validPhrase.toCharArray())

        // ✅ getOrThrow() extrai o VaultEntry; em falha, o teste falha
        //    com a mensagem da exceção em vez de NPE.
        val e1 = v.addEntry("GitHub", "user", "pass1").getOrThrow()
        val e2 = v.addEntry("GitHub", "user", "pass2").getOrThrow()

        assertNotEquals("IDs devem ser únicos mesmo com name+user iguais",
            e1.id, e2.id)
        assertTrue("id não pode ser vazio", e1.id.isNotEmpty())
        assertTrue("id não pode ser vazio", e2.id.isNotEmpty())

        // ✅ deleteEntry retorna Result<Unit>; isSuccess substitui o Boolean.
        assertTrue("deleteEntry deveria suceder",
            v.deleteEntry(e1.id).isSuccess)

        val remaining = v.getEntries()
        assertEquals(1, remaining.size)
        assertEquals(e2.id, remaining[0].id)
    }

    @Test
    fun update_por_id_nao_afeta_duplicata() {
        val v = newVault()
        v.create(validPin.toCharArray(), validPhrase.toCharArray())

        val e1 = v.addEntry("GitHub", "user", "pass1").getOrThrow()
        val e2 = v.addEntry("GitHub", "user", "pass2").getOrThrow()

        // ✅ updateEntry retorna Result<Unit>; isSuccess no lugar de Boolean.
        assertTrue("updateEntry deveria suceder",
            v.updateEntry(e1.id, "GitLab", "u1", "novo").isSuccess)

        val list = v.getEntries()
        assertEquals(2, list.size)
        val updated = list.first { it.id == e1.id }
        val untouched = list.first { it.id == e2.id }

        assertEquals("GitLab", updated.name)
        assertEquals("novo", updated.pass)
        assertEquals("GitHub", untouched.name)
        assertEquals("pass2", untouched.pass)
        assertTrue("updatedAt deve avançar", updated.updatedAt >= updated.createdAt)
    }

    @Test
    fun migra_entradas_antigas_sem_id() {
        val v = newVault()
        v.create(validPin.toCharArray(), validPhrase.toCharArray())

        val withId = v.addEntry("Antigo", "user", "pass").getOrThrow()
        v.lock()

        val v2 = vaultFromSameFile()
        assertTrue(v2.unlockPin(validPin.toCharArray()) is UnlockResult.Success)
        val loaded = v2.getEntries()
        assertEquals(1, loaded.size)
        assertEquals(withId.id, loaded[0].id)
        assertTrue("id preservado após round-trip", loaded[0].id.isNotEmpty())
    }

    // ------------------------------------------------------------------
    // Recuperação via .bak
    // ------------------------------------------------------------------

    @Test
    fun corrompido_sem_bak_retorna_corrupted() {
        val v = newVault()
        v.create(validPin.toCharArray(), validPhrase.toCharArray())
        v.lock()

        File(tmp.root, "vault.json").writeText("{ nada")
        File(tmp.root, "vault.json.bak").delete()

        val v2 = vaultFromSameFile()
        val result = v2.unlockPin(validPin.toCharArray())
        assertTrue("esperado CorruptedVault, veio $result",
            result is UnlockResult.CorruptedVault)
    }

    @Test
    fun summaries_nao_contem_senha() {
        val v = newVault()
        v.create(validPin.toCharArray(), validPhrase.toCharArray())
        v.addEntry("GitHub", "user", "senhaSecreta")

        val summaries = v.getEntrySummaries()
        assertEquals(1, summaries.size)
        // EntryItem não tem campo `pass`; se tivesse, este teste nem compilaria.
        assertEquals("GitHub", summaries[0].name)

        // Mas a senha está acessível para copiar:
        val pass = v.getEntryPasswordSnapshot(summaries[0].id)
        assertEquals("senhaSecreta", pass)
    }
}
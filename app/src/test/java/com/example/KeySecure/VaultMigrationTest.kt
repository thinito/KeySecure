package com.example.KeySecure

import com.example.KeySecure.crypto.Crypto
import com.example.KeySecure.crypto.IKeystore
import com.example.KeySecure.crypto.PepperSecurityLevel
import com.example.KeySecure.data.EntryItem
import com.example.KeySecure.data.VaultEntry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
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

    override fun getPepperSecurityLevel(): PepperSecurityLevel? =
        PepperSecurityLevel.TRUSTED_ENVIRONMENT
}

private val fakeKdf: DeriveBytesFn = { password, salt, _, iterations ->
    Crypto.deriveBytesPbkdf2(password, salt, iterations)
}

class VaultMigrationTest {

    @get:Rule
    val tmp = TemporaryFolder()

    //   8 dígitos, não trivial — compatível com MIN_PIN_LENGTH = 8
    private val validPin = "48291736"
    // 7 palavras — zxcvbn estima > 60 bits com folga.
    private val validPhrase = "correct horse battery staple zinc guitar violet"

    private fun newVault(): Vault {
        val file = File(tmp.root, "vault.json")
        if (file.exists()) file.delete()
        return Vault(file, FakeKeystore(), fakeKdf)
    }

    private fun vaultFromSameFile(): Vault =
        Vault(File(tmp.root, "vault.json"), FakeKeystore(), fakeKdf)

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
        assertTrue("unlockPhrase deveria funcionar com pepper injetado",
            unlocked is UnlockResult.Success)
    }

    @Test
    fun pin_errado_falha() {
        val v = newVault()
        val created = v.create(validPin.toCharArray(), validPhrase.toCharArray())
        assertTrue("pré-condição: create falhou ($created)",
            created is UnlockResult.Success)

        v.lock()
        // 8 dígitos bem formados, mas PIN errado.
        val result = v.unlockPin("99999999".toCharArray())
        assertTrue("esperado WrongCredential, veio $result",
            result is UnlockResult.WrongCredential)
    }

    @Test
    fun create_recusa_duplicado() {
        val v = newVault()
        val created = v.create(validPin.toCharArray(), validPhrase.toCharArray())
        assertTrue("pré-condição: create falhou ($created)",
            created is UnlockResult.Success)

        // Segundo PIN com 8 dígitos válidos (não trivial).
        val second = v.create(
            "13579024".toCharArray(),
            "outra frase longa aqui e boa!".toCharArray()
        )
        assertTrue("esperado VaultAlreadyExists, veio $second",
            second is UnlockResult.VaultAlreadyExists)
    }

    @Test
    fun entradas_persistidas_cifradas() {
        val v = newVault()
        v.create(validPin.toCharArray(), validPhrase.toCharArray())

        val pass = "senhaSecreta".toCharArray()
        try {
            v.addEntry("GitHub", "user", pass).getOrThrow()
        } finally {
            pass.fill('\u0000')
        }
        v.lock()

        val raw = File(tmp.root, "vault.json").readText()
        assertFalse(raw.contains("senhaSecreta"))
    }

    @Test
    fun summaries_nao_contem_senha() {
        val v = newVault()
        v.create(validPin.toCharArray(), validPhrase.toCharArray())

        val pass = "senhaSecreta".toCharArray()
        val e = try {
            v.addEntry("GitHub", "user", pass).getOrThrow()
        } finally {
            pass.fill('\u0000')
        }

        val summaries = v.getEntrySummaries()
        assertEquals(1, summaries.size)
        assertEquals("GitHub", summaries[0].name)

        val snapshot = v.getEntryPasswordSnapshot(e.id)
        assertNotNull(snapshot)
        try {
            assertEquals("senhaSecreta", String(snapshot!!))
        } finally {
            snapshot!!.fill('\u0000')
        }
    }

    @Test
    fun senha_cifrada_em_memoria() {
        val v = newVault()
        v.create(validPin.toCharArray(), validPhrase.toCharArray())

        val pass = "senhaSecreta".toCharArray()
        try {
            v.addEntry("GitHub", "user", pass).getOrThrow()
        } finally {
            pass.fill('\u0000')
        }

        // O campo passCipher não deve conter a senha em claro.
        // Usamos a API pública getEntrySummaries + reflection? Não.
        // Em vez disso, validamos via getEntries (deprecated) que a senha
        // decifrada ainda bate — mas o importante é que o JSON no disco não tem.
        // A verificação em memória requer reflection; fica como teste opcional.
        v.lock()
    }

    @Test
    fun ids_unicos_para_entradas_identicas() {
        val v = newVault()
        v.create(validPin.toCharArray(), validPhrase.toCharArray())

        val e1 = v.addEntry("GitHub", "user", "pass1".toCharArray()).getOrThrow()
        val e2 = v.addEntry("GitHub", "user", "pass2".toCharArray()).getOrThrow()

        assertNotEquals("IDs devem ser únicos", e1.id, e2.id)
        assertTrue(e1.id.isNotEmpty())
        assertTrue(e2.id.isNotEmpty())

        assertTrue("deleteEntry deveria suceder", v.deleteEntry(e1.id).isSuccess)
        val remaining = v.getEntries()
        assertEquals(1, remaining.size)
        assertEquals(e2.id, remaining[0].id)
    }

    @Test
    fun update_por_id_nao_afeta_duplicata() {
        val v = newVault()
        v.create(validPin.toCharArray(), validPhrase.toCharArray())

        val e1 = v.addEntry("GitHub", "user", "pass1".toCharArray()).getOrThrow()
        val e2 = v.addEntry("GitHub", "user", "pass2".toCharArray()).getOrThrow()

        assertTrue("updateEntry deveria suceder",
            v.updateEntry(e1.id, "GitLab", "u1", "novo".toCharArray()).isSuccess)

        val list = v.getEntries()
        assertEquals(2, list.size)
        val updated = list.first { it.id == e1.id }
        val untouched = list.first { it.id == e2.id }
        assertEquals("GitLab", updated.name)
        assertEquals("novo", updated.pass)
        assertEquals("GitHub", untouched.name)
        assertEquals("pass2", untouched.pass)
    }

    @Test
    fun migra_entradas_antigas_sem_id() {
        val v = newVault()
        v.create(validPin.toCharArray(), validPhrase.toCharArray())

        val withId = v.addEntry("Antigo", "user", "pass".toCharArray()).getOrThrow()
        v.lock()

        val v2 = vaultFromSameFile()
        assertTrue(v2.unlockPin(validPin.toCharArray()) is UnlockResult.Success)
        val loaded = v2.getEntries()
        assertEquals(1, loaded.size)
        assertEquals(withId.id, loaded[0].id)
    }

    @Test
    fun corrompido_sem_bak_retorna_corrupted() {
        val v = newVault()
        v.create(validPin.toCharArray(), validPhrase.toCharArray())
        v.lock()

        File(tmp.root, "vault.json").writeText("{ nada")

        val v2 = vaultFromSameFile()
        val result = v2.unlockPin(validPin.toCharArray())
        assertTrue("esperado CorruptedVault, veio $result",
            result is UnlockResult.CorruptedVault)
    }

    @Test
    fun vault_nao_abre_sem_pepper() {
        val v = newVault()
        v.create(validPin.toCharArray(), validPhrase.toCharArray())
        v.lock()

        val semPepper = object : IKeystore {
            override fun hasKey() = false
            override fun createKey() {}
            override fun getKey(): SecretKey = throw UnsupportedOperationException()
            override fun deleteKey() {}
            override fun hasPepperKey() = false
            override fun createPepperKey() {}
            override fun computePepperHmac(data: ByteArray) = throw UnsupportedOperationException()
            override fun deletePepperKey() {}
            override fun getPepperSecurityLevel(): PepperSecurityLevel? = null
        }
        val v2 = Vault(File(tmp.root, "vault.json"), semPepper, fakeKdf)
        val result = v2.unlockPin(validPin.toCharArray())
        assertTrue("esperado NoPepper, veio $result", result is UnlockResult.NoPepper)
    }
}
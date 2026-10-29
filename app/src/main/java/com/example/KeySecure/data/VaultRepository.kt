package com.example.KeySecure.data

import com.example.KeySecure.UnlockResult
import com.example.KeySecure.Vault
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import javax.crypto.Cipher

/**
 * Fachada única sobre o [Vault].
 *
 *  - Expõe um único `StateFlow<VaultState>` (consolidando `exists` + `unlocked`).
 *  - Delega todas as operações do cofre — ViewModels e UI nunca veem o
 *    [Vault] cru. Isso garante que não há como criar uma segunda instância.
 *
 * Senhas: `addEntry`, `updateEntry` e `getEntryPasswordSnapshot` trabalham
 * com `CharArray` (zeráveis pelo caller). Strings aparecem apenas
 * internamente no `Vault`, durante o decode/persist do JSON.
 */
class VaultRepository(
    private val vault: Vault,
    scope: CoroutineScope
) {

    val state: StateFlow<VaultState> = combine(
        vault.exists,
        vault.unlocked
    ) { exists, unlocked ->
        when {
            !exists -> VaultState.NotCreated
            unlocked -> VaultState.Unlocked
            else -> VaultState.Locked
        }
    }.stateIn(
        scope = scope,
        started = SharingStarted.Eagerly,
        initialValue = initialState(vault)
    )

    private fun initialState(v: Vault): VaultState = when {
        !v.fileExists() -> VaultState.NotCreated
        v.unlocked.value -> VaultState.Unlocked
        else -> VaultState.Locked
    }

    // ==================================================================
    // Criação / desbloqueio
    // ==================================================================
    fun create(pin: CharArray, passphrase: CharArray): UnlockResult =
        vault.create(pin, passphrase)

    fun unlockPin(pin: CharArray): UnlockResult =
        vault.unlockPin(pin)

    fun unlockPhrase(phrase: CharArray): UnlockResult =
        vault.unlockPhrase(phrase)

    fun unlockWithKeystoreCipher(cipher: Cipher): UnlockResult =
        vault.unlockWithKeystoreCipher(cipher)

    // ==================================================================
    // Ciclo de vida
    // ==================================================================
    fun lock() = vault.lock()
    fun fileExists(): Boolean = vault.fileExists()

    // ==================================================================
    // Biometria
    // ==================================================================
    fun enrollBiometric(cipher: Cipher): UnlockResult =
        vault.enrollBiometric(cipher)

    fun hasBiometricEnrollment(): Boolean = vault.hasBiometricEnrollment()

    fun getBiometricIv(): ByteArray? = vault.getBiometricIv()

    fun disableBiometric(): UnlockResult = vault.disableBiometric()

    // ==================================================================
    // Troca de credenciais
    // ==================================================================
    fun changePin(currentPin: CharArray, newPin: CharArray): UnlockResult =
        vault.changePin(currentPin, newPin)

    fun changePassphrase(currentPhrase: CharArray, newPhrase: CharArray): UnlockResult =
        vault.changePassphrase(currentPhrase, newPhrase)

    fun needsIterationUpgrade(): Boolean = vault.needsIterationUpgrade()

    fun upgradeIterations(pin: CharArray, phrase: CharArray): UnlockResult =
        vault.upgradeIterations(pin, phrase)

    // ==================================================================
    // CRUD — pass é CharArray (zerável)
    // ==================================================================
    fun getEntrySummaries(): List<EntryItem> = vault.getEntrySummaries()

    /**
     * Decifra a senha sob demanda. O caller **deve** zerar o CharArray
     * retornado (`pass.fill('\u0000')`) após o uso.
     */
    fun getEntryPasswordSnapshot(id: String): CharArray? =
        vault.getEntryPasswordSnapshot(id)

    fun addEntry(name: String, user: String, pass: CharArray): Result<EntryItem> =
        vault.addEntry(name, user, pass)

    fun updateEntry(id: String, name: String, user: String, pass: CharArray): Result<Unit> =
        vault.updateEntry(id, name, user, pass)

    fun deleteEntry(id: String): Result<Unit> = vault.deleteEntry(id)
}
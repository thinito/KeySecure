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
 * Responsabilidades:
 *  1. Expor um **único** `StateFlow<VaultState>` (consolida `exists` + `unlocked`).
 *  2. Delegar todas as operações do cofre — ViewModels e UI nunca veem o
 *     [Vault] cru. Isso garante que não há como criar uma segunda instância
 *     por engano.
 *
 * A instância de [Vault] é passada pelo `KeySecureApp`; o `VaultRepository`
 * em si é um singleton lá, criado com escopo de aplicação.
 */
class VaultRepository(
    private val vault: Vault,
    scope: CoroutineScope
) {

    /**
     * Estado consolidado. Emitido a cada mudança de `vault.exists` ou
     * `vault.unlocked`. `SharingStarted.Eagerly` inicia a coleta no
     * momento da criação do repositório, garantindo que a UI sempre
     * veja o estado mais recente ao se inscrever.
     */
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
    // CRUD de entradas — sem segredos
    // ==================================================================
    fun getEntrySummaries(): List<EntryItem> = vault.getEntrySummaries()

    fun getEntryPasswordSnapshot(id: String): String? =
        vault.getEntryPasswordSnapshot(id)

    fun addEntry(name: String, user: String, pass: String): Result<EntryItem> =
        vault.addEntry(name, user, pass)

    fun updateEntry(id: String, name: String, user: String, pass: String): Result<Unit> =
        vault.updateEntry(id, name, user, pass)

    fun deleteEntry(id: String): Result<Unit> = vault.deleteEntry(id)
}
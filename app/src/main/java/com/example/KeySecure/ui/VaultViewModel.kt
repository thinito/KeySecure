package com.example.KeySecure.ui

import android.app.Application
import android.content.Context
import android.util.Log
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.KeySecure.KeySecureApp
import com.example.KeySecure.R
import com.example.KeySecure.UnlockResult
import com.example.KeySecure.data.EntryItem
import com.example.KeySecure.util.ClipboardUtil
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Estado de uma operação pesada (changePin / changePassphrase / upgradeIterations).
 * Um único StateFlow atende os três diálogos, porque apenas um fica aberto por vez.
 */
data class VaultOpState(
    val isProcessing: Boolean = false,
    val error: String? = null,
    val success: Boolean = false
)

class VaultViewModel(app: Application) : AndroidViewModel(app) {

    private val keyApp = app as KeySecureApp
    private val vault = keyApp.vault
    private val tracker = keyApp.attemptTracker

    private val _entries = MutableStateFlow<List<EntryItem>>(emptyList())
    val entries: StateFlow<List<EntryItem>> = _entries.asStateFlow()

    private val _lastError = MutableStateFlow<String?>(null)
    val lastError: StateFlow<String?> = _lastError.asStateFlow()

    // ✅ Estado das operações pesadas (changePin/Phrase/upgrade)
    private val _opState = MutableStateFlow(VaultOpState())
    val opState: StateFlow<VaultOpState> = _opState.asStateFlow()

    init {
        viewModelScope.launch {
            vault.unlocked.collect { if (it) refresh() else _entries.value = emptyList() }
        }
    }

    fun refresh() { _entries.value = vault.getEntrySummaries() }

    fun add(name: String, user: String, pass: String): Result<EntryItem> {
        val r = vault.addEntry(name, user, pass); handle(r); return r
    }

    fun update(id: String, name: String, user: String, pass: String): Result<Unit> {
        val r = vault.updateEntry(id, name, user, pass); handle(r); return r
    }

    fun delete(id: String): Result<Unit> {
        val r = vault.deleteEntry(id); handle(r); return r
    }

    fun copyPassword(ctx: Context, id: String) {
        val pass = vault.getEntryPasswordSnapshot(id) ?: return
        ClipboardUtil.copySensitive(ctx, "senha", pass)
    }

    fun getPasswordForEdit(id: String): String? = vault.getEntryPasswordSnapshot(id)

    fun lock() = vault.lock()
    fun clearError() { _lastError.value = null }

    fun needsIterationUpgrade(): Boolean = vault.needsIterationUpgrade()

    // ==================================================================
    // Operações pesadas — sempre em Dispatchers.Default
    // ==================================================================

    /** Limpa o estado antes de abrir um novo diálogo. */
    fun resetOpState() {
        _opState.value = VaultOpState()
    }

    fun changePin(current: String, new: String) {
        runVaultOp(R.string.error_change_failed) {
            vault.changePin(current.toCharArray(), new.toCharArray())
        }
    }

    fun changePassphrase(current: String, new: String) {
        runVaultOp(R.string.error_change_failed) {
            vault.changePassphrase(current.toCharArray(), new.toCharArray())
        }
    }

    fun upgradeIterations(pin: String, phrase: String) {
        runVaultOp(R.string.error_change_failed) {
            vault.upgradeIterations(pin.toCharArray(), phrase.toCharArray())
        }
    }

    /**
     * Executa `op` em Dispatchers.Default — PBKDF2 (600k iterações) +
     * read/decrypt/migrate/persist ficam fora do main thread.
     * `isProcessing` é setado **sincronamente** antes do launch,
     * impedindo duplo toque disparar duas derivações.
     */
    private fun runVaultOp(genericErrorRes: Int, op: () -> UnlockResult) {
        if (_opState.value.isProcessing) return
        val app = getApplication<Application>()
        _opState.value = VaultOpState(isProcessing = true)

        viewModelScope.launch {
            val result = withContext(Dispatchers.Default) {
                try {
                    op()
                } catch (t: Throwable) {
                    Log.e(TAG, "Falha inesperada em operação do cofre", t)
                    UnlockResult.Failure(t)
                }
            }

            val newState = when (result) {
                is UnlockResult.Success -> {
                    withContext(Dispatchers.IO) { runCatching { tracker.reset() } }
                    VaultOpState(success = true)
                }
                is UnlockResult.WrongCredential ->
                    VaultOpState(error = app.getString(R.string.error_wrong_credential))
                is UnlockResult.NoPepper ->
                    VaultOpState(error = app.getString(R.string.error_no_pepper))
                is UnlockResult.LegacyVaultNoPepper ->
                    VaultOpState(error = app.getString(R.string.error_legacy_vault))
                is UnlockResult.VaultAlreadyExists ->
                    VaultOpState(error = app.getString(R.string.error_vault_already_exists))
                is UnlockResult.RollbackDetected ->
                    VaultOpState(error = app.getString(R.string.error_rollback_detected))
                is UnlockResult.CorruptedVault ->
                    VaultOpState(error = app.getString(R.string.error_vault_corrupted))
                is UnlockResult.NoVault ->
                    VaultOpState(error = app.getString(R.string.error_no_vault))
                is UnlockResult.Aborted ->
                    VaultOpState(error = app.getString(genericErrorRes))
                is UnlockResult.Failure -> {
                    Log.e(TAG, "Falha em operação do cofre", result.cause)
                    VaultOpState(error = app.getString(genericErrorRes))
                }
            }
            _opState.value = newState
        }
    }

    private fun handle(result: Result<*>) {
        result.onSuccess {
            _lastError.value = null
            refresh()
        }.onFailure {
            _lastError.value = it.message ?: it.javaClass.simpleName
        }
    }

    private companion object {
        private const val TAG = "VaultViewModel"
    }
}
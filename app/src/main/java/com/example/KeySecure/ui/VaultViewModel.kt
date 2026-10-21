package com.example.KeySecure.ui

import android.app.Application
import android.content.Context
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

class VaultViewModel(app: Application) : AndroidViewModel(app) {

    private val keyApp = app as KeySecureApp
    private val vault = keyApp.vault
    private val tracker = keyApp.attemptTracker

    private val _entries = MutableStateFlow<List<EntryItem>>(emptyList())
    val entries: StateFlow<List<EntryItem>> = _entries.asStateFlow()

    private val _lastError = MutableStateFlow<String?>(null)
    val lastError: StateFlow<String?> = _lastError.asStateFlow()

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

    // ==================================================================
    // Troca de credenciais
    // ==================================================================
    fun changePin(currentPin: String, newPin: String): Result<Unit> =
        runVaultOp { vault.changePin(currentPin.toCharArray(), newPin.toCharArray()) }

    fun changePassphrase(currentPhrase: String, newPhrase: String): Result<Unit> =
        runVaultOp { vault.changePassphrase(currentPhrase.toCharArray(), newPhrase.toCharArray()) }

    fun upgradeIterations(pin: String, phrase: String): Result<Unit> =
        runVaultOp { vault.upgradeIterations(pin.toCharArray(), phrase.toCharArray()) }

    fun needsIterationUpgrade(): Boolean = vault.needsIterationUpgrade()

    // ==================================================================
    // Helpers
    // ==================================================================
    private fun runVaultOp(op: () -> UnlockResult): Result<Unit> {
        val app = getApplication<Application>()
        return when (val result = op()) {
            is UnlockResult.Success -> {
                viewModelScope.launch(Dispatchers.IO) { tracker.reset() }
                Result.success(Unit)
            }
            is UnlockResult.WrongCredential -> {
                val msg = app.getString(R.string.error_wrong_credential)
                _lastError.value = msg
                Result.failure(IllegalArgumentException(msg))
            }
            is UnlockResult.NoVault -> {
                val msg = app.getString(R.string.error_no_vault)
                _lastError.value = msg
                Result.failure(IllegalStateException(msg))
            }
            is UnlockResult.CorruptedVault -> {
                val msg = app.getString(R.string.error_vault_corrupted)
                _lastError.value = msg
                Result.failure(IllegalStateException(msg))
            }
            is UnlockResult.NoPepper -> {
                val msg = app.getString(R.string.error_no_pepper)
                _lastError.value = msg
                Result.failure(IllegalStateException(msg))
            }
            is UnlockResult.LegacyVaultNoPepper -> {
                val msg = app.getString(R.string.error_legacy_vault)
                _lastError.value = msg
                Result.failure(IllegalStateException(msg))
            }
            is UnlockResult.Aborted -> Result.failure(IllegalStateException("Abortado"))
            is UnlockResult.Failure -> {
                _lastError.value = result.cause.message ?: "Erro"
                Result.failure(result.cause)
            }
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
}
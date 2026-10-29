package com.example.KeySecure.ui

import android.app.Application
import android.content.Context
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.KeySecure.KeySecureApp
import com.example.KeySecure.LockTimeoutHandler
import com.example.KeySecure.R
import com.example.KeySecure.UnlockResult
import com.example.KeySecure.data.EntryItem
import com.example.KeySecure.data.SecurityPolicy
import com.example.KeySecure.data.VaultState
import com.example.KeySecure.util.ClipboardUtil
import com.example.KeySecure.util.SafeLog
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

data class VaultOpState(
    val isProcessing: Boolean = false,
    val error: String? = null,
    val success: Boolean = false
)

class VaultViewModel(app: Application) : AndroidViewModel(app) {

    private val keyApp = app as KeySecureApp
    private val vaultRepository = keyApp.vaultRepository
    private val tracker = keyApp.attemptTracker
    private val lockPreferences = keyApp.lockPreferences

    private val _entries = MutableStateFlow<List<EntryItem>>(emptyList())
    val entries: StateFlow<List<EntryItem>> = _entries.asStateFlow()

    private val _lastError = MutableStateFlow<String?>(null)
    val lastError: StateFlow<String?> = _lastError.asStateFlow()

    private val _opState = MutableStateFlow(VaultOpState())
    val opState: StateFlow<VaultOpState> = _opState.asStateFlow()

    private val _lockTimeout = MutableStateFlow(lockPreferences.getTimeout())
    val lockTimeout: StateFlow<SecurityPolicy.LockTimeout> = _lockTimeout.asStateFlow()

    init {
        viewModelScope.launch {
            vaultRepository.state.collect { s ->
                if (s is VaultState.Unlocked) refresh()
                else _entries.value = emptyList()
            }
        }
    }

    fun refresh() { _entries.value = vaultRepository.getEntrySummaries() }

    // ==================================================================
    // CRUD — pass é CharArray
    // ==================================================================
    fun add(name: String, user: String, pass: CharArray): Result<EntryItem> {
        val r = vaultRepository.addEntry(name, user, pass)
        handle(r)
        return r
    }

    fun update(id: String, name: String, user: String, pass: CharArray): Result<Unit> {
        val r = vaultRepository.updateEntry(id, name, user, pass)
        handle(r)
        return r
    }

    fun delete(id: String): Result<Unit> {
        val r = vaultRepository.deleteEntry(id)
        handle(r)
        return r
    }

    /**
     * Copia a senha para o clipboard. A senha é decifrada em CharArray e
     * zerada logo após a cópia. A `String` criada por [ClipboardUtil] é
     * inevitável (API do sistema exige `CharSequence`) e o worker de
     * limpeza cuida de apagá-la em 30s.
     */
    fun copyPassword(ctx: Context, id: String) {
        val pass = vaultRepository.getEntryPasswordSnapshot(id) ?: return
        try {
            ClipboardUtil.copySensitive(ctx, "senha", String(pass))
        } finally {
            pass.fill('\u0000')
        }
    }

    /**
     * Retorna a senha como `String` para pré-preencher o diálogo de edição.
     * A `String` existe apenas enquanto o diálogo está aberto; o caller
     * descarta a referência ao fechá-lo.
     */
    fun getPasswordForEdit(id: String): String? {
        val pass = vaultRepository.getEntryPasswordSnapshot(id) ?: return null
        return try {
            String(pass)
        } finally {
            pass.fill('\u0000')
        }
    }

    fun lock() = vaultRepository.lock()
    fun clearError() { _lastError.value = null }
    fun needsIterationUpgrade(): Boolean = vaultRepository.needsIterationUpgrade()

    fun resetOpState() { _opState.value = VaultOpState() }

    fun setLockTimeout(timeout: SecurityPolicy.LockTimeout) {
        lockPreferences.setTimeout(timeout)
        LockTimeoutHandler.setTimeout(timeout)
        _lockTimeout.value = timeout
    }

    fun changePin(current: String, new: String) {
        runVaultOp(R.string.error_change_failed) {
            vaultRepository.changePin(current.toCharArray(), new.toCharArray())
        }
    }

    fun changePassphrase(current: String, new: String) {
        runVaultOp(R.string.error_change_failed) {
            vaultRepository.changePassphrase(current.toCharArray(), new.toCharArray())
        }
    }

    fun upgradeIterations(pin: String, phrase: String) {
        runVaultOp(R.string.error_change_failed) {
            vaultRepository.upgradeIterations(pin.toCharArray(), phrase.toCharArray())
        }
    }

    private fun runVaultOp(genericErrorRes: Int, op: () -> UnlockResult) {
        if (_opState.value.isProcessing) return
        val app = getApplication<Application>()
        _opState.value = VaultOpState(isProcessing = true)

        viewModelScope.launch {
            val result = withContext(Dispatchers.Default) {
                try {
                    op()
                } catch (t: Throwable) {
                    SafeLog.e(TAG, "Exceção inesperada em operação do Vault", t)
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
                    SafeLog.e(TAG, "Falha em operação do Vault", result.cause)
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
            SafeLog.e(TAG, "Falha em operação de entrada", it)
            _lastError.value = it.message ?: it.javaClass.simpleName
        }
    }

    private companion object {
        private const val TAG = "VaultViewModel"
    }
}
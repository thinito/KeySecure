package com.example.KeySecure.ui

import android.app.Application
import android.util.Log
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.KeySecure.KeySecureApp
import com.example.KeySecure.R
import com.example.KeySecure.UnlockResult
import com.example.KeySecure.data.SecurityPolicy
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

data class UnlockState(
    val pin: String = "",
    val phrase: String = "",
    val usePhrase: Boolean = false,
    val error: String? = null,
    val lockoutRemainingSec: Int = 0,
    val isProcessing: Boolean = false,
    val vaultCorrupted: Boolean = false,
    val legacyVault: Boolean = false,
    val pepperMissing: Boolean = false
) {
    val isLocked: Boolean get() = lockoutRemainingSec > 0
}

private sealed class UnlockOutcome {
    object Success : UnlockOutcome()
    object WrongCredential : UnlockOutcome()
    object Locked : UnlockOutcome()
    object BadFormat : UnlockOutcome()
    object NoVault : UnlockOutcome()
    object CorruptedVault : UnlockOutcome()
    object NoPepper : UnlockOutcome()
    object LegacyVaultNoPepper : UnlockOutcome()
    object Aborted : UnlockOutcome()
    object RollbackDetected : UnlockOutcome()
    object VaultAlreadyExists : UnlockOutcome()
    data class Failure(val cause: Throwable) : UnlockOutcome()
}

class UnlockViewModel(app: Application) : AndroidViewModel(app) {

    private val keyApp = app as KeySecureApp
    private val vault = keyApp.vault
    private val tracker = keyApp.attemptTracker

    private val _state = MutableStateFlow(UnlockState())
    val state = _state.asStateFlow()

    private var submitJob: Job? = null
    private var countdownJob: Job? = null

    init {
        viewModelScope.launch(Dispatchers.IO) { refreshLockoutSuspend() }
        viewModelScope.launch {
            vault.unlocked.collect { isUnlocked ->
                if (!isUnlocked) {
                    countdownJob?.cancel()
                    _state.value = UnlockState()
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Lockout
    // ------------------------------------------------------------------
    private suspend fun refreshLockoutSuspend() {
        val remainMs = if (tracker.isLockedOut()) tracker.remainingMs() else 0L
        withContext(Dispatchers.Main) {
            if (remainMs > 0) {
                _state.update { it.copy(lockoutRemainingSec = (remainMs / 1000).toInt()) }
                startCountdown()
            } else {
                _state.update { it.copy(lockoutRemainingSec = 0) }
            }
        }
    }

    private fun startCountdown() {
        countdownJob?.cancel()
        countdownJob = viewModelScope.launch {
            while (_state.value.lockoutRemainingSec > 0) {
                delay(1000)
                _state.update {
                    it.copy(lockoutRemainingSec = (it.lockoutRemainingSec - 1).coerceAtLeast(0))
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Input
    // ------------------------------------------------------------------
    fun onPinChange(value: String) {
        if (_state.value.isProcessing) return
        if (value.length <= SecurityPolicy.MAX_PIN_LENGTH && value.all { it in '0'..'9' }) {
            _state.update { it.copy(pin = value, error = null) }
        }
    }

    fun onPhraseChange(value: String) {
        if (_state.value.isProcessing) return
        _state.update { it.copy(phrase = value, error = null) }
    }

    fun toggleUsePhrase() {
        if (_state.value.isProcessing) return
        _state.update { it.copy(usePhrase = !it.usePhrase, error = null) }
    }

    // ------------------------------------------------------------------
    // Submit — trabalho pesado em Dispatchers.Default
    // ------------------------------------------------------------------
    fun submit() {
        val s = _state.value
        // Guarda dupla: isProcessing e isLocked. Ambas checadas antes de
        // qualquer trabalho, para rejeitar cliques adicionais imediatamente.
        if (s.isProcessing || s.isLocked) return

        // ✅ Marca isProcessing SÍNCRONO antes de lançar a coroutine.
        // Se o usuário der dois toques em sequência rápida, o segundo
        // submit() vê isProcessing == true e retorna — sem dupla derivação.
        _state.update { it.copy(isProcessing = true, error = null) }

        submitJob?.cancel()
        submitJob = viewModelScope.launch {
            val usePhrase = s.usePhrase
            val pinSnapshot = s.pin
            val phraseSnapshot = s.phrase
            val pinChars = if (usePhrase) null else pinSnapshot.toCharArray()
            val phraseChars = if (usePhrase) phraseSnapshot.toCharArray() else null

            // ✅ PBKDF2 (600k iterações) + decrypt + decode + migração
            //    rodam em Dispatchers.Default. A UI fica livre.
            val outcome: UnlockOutcome = withContext(Dispatchers.Default) {
                try {
                    if (usePhrase) {
                        when {
                            !SecurityPolicy.isWellFormedPassphrase(phraseSnapshot) ->
                                UnlockOutcome.BadFormat
                            tracker.isLockedOut() ->
                                UnlockOutcome.Locked
                            else ->
                                vault.unlockPhrase(phraseChars!!).toOutcome()
                        }
                    } else {
                        when {
                            !SecurityPolicy.isWellFormedPin(pinSnapshot) ->
                                UnlockOutcome.BadFormat
                            tracker.isLockedOut() ->
                                UnlockOutcome.Locked
                            else ->
                                vault.unlockPin(pinChars!!).toOutcome()
                        }
                    }
                } catch (t: Throwable) {
                    Log.e(TAG, "Falha inesperada no desbloqueio", t)
                    UnlockOutcome.Failure(t)
                } finally {
                    pinChars?.fill('\u0000')
                    phraseChars?.fill('\u0000')
                }
            }

            // Registro de falha / reset só quando aplicável, em IO
            when (outcome) {
                is UnlockOutcome.WrongCredential ->
                    withContext(Dispatchers.IO) { tracker.registerFailure() }
                is UnlockOutcome.Success ->
                    withContext(Dispatchers.IO) { tracker.reset() }
                else -> { /* Locked/BadFormat/Aborted/etc: nada */ }
            }

            applyOutcome(outcome, usePhrase)
        }
    }

    private fun applyOutcome(outcome: UnlockOutcome, usePhrase: Boolean) {
        val app = getApplication<Application>()
        when (outcome) {
            is UnlockOutcome.Success -> {
                _state.update {
                    it.copy(pin = "", phrase = "", error = null, isProcessing = false)
                }
            }
            is UnlockOutcome.WrongCredential -> {
                _state.update {
                    it.copy(
                        pin = if (usePhrase) it.pin else "",
                        error = app.getString(R.string.error_wrong_credential),
                        isProcessing = false
                    )
                }
                viewModelScope.launch(Dispatchers.IO) { refreshLockoutSuspend() }
            }
            is UnlockOutcome.Locked -> {
                _state.update { it.copy(isProcessing = false) }
                viewModelScope.launch(Dispatchers.IO) { refreshLockoutSuspend() }
            }
            is UnlockOutcome.BadFormat -> {
                val msg = if (usePhrase) {
                    app.getString(
                        R.string.error_phrase_format,
                        SecurityPolicy.MIN_PASSPHRASE_LENGTH
                    )
                } else {
                    app.getString(
                        R.string.error_pin_format,
                        SecurityPolicy.MIN_PIN_LENGTH,
                        SecurityPolicy.MAX_PIN_LENGTH
                    )
                }
                _state.update { it.copy(error = msg, isProcessing = false) }
            }
            is UnlockOutcome.NoVault -> {
                _state.update {
                    it.copy(error = app.getString(R.string.error_no_vault), isProcessing = false)
                }
            }
            is UnlockOutcome.CorruptedVault -> {
                _state.update {
                    it.copy(
                        error = app.getString(R.string.error_vault_corrupted),
                        vaultCorrupted = true,
                        isProcessing = false
                    )
                }
            }
            is UnlockOutcome.NoPepper -> {
                _state.update {
                    it.copy(
                        error = app.getString(R.string.error_no_pepper),
                        pepperMissing = true,
                        usePhrase = true,
                        isProcessing = false
                    )
                }
            }
            is UnlockOutcome.LegacyVaultNoPepper -> {
                _state.update {
                    it.copy(
                        error = app.getString(R.string.error_legacy_vault),
                        legacyVault = true,
                        usePhrase = true,
                        isProcessing = false
                    )
                }
            }
            is UnlockOutcome.RollbackDetected -> {
                _state.update {
                    it.copy(
                        error = app.getString(R.string.error_rollback_detected),
                        vaultCorrupted = true,
                        isProcessing = false
                    )
                }
            }
            is UnlockOutcome.VaultAlreadyExists -> {
                _state.update {
                    it.copy(
                        error = app.getString(R.string.error_vault_already_exists),
                        isProcessing = false
                    )
                }
            }
            is UnlockOutcome.Aborted -> {
                _state.update { it.copy(isProcessing = false) }
            }
            is UnlockOutcome.Failure -> {
                _state.update {
                    it.copy(
                        error = app.getString(R.string.error_unexpected),
                        isProcessing = false
                    )
                }
            }
        }
    }

    override fun onCleared() {
        super.onCleared()
        countdownJob?.cancel()
        submitJob?.cancel()
    }

    private companion object {
        private const val TAG = "UnlockViewModel"
    }
}

private fun UnlockResult.toOutcome(): UnlockOutcome = when (this) {
    UnlockResult.Success -> UnlockOutcome.Success
    UnlockResult.WrongCredential -> UnlockOutcome.WrongCredential
    UnlockResult.NoVault -> UnlockOutcome.NoVault
    UnlockResult.CorruptedVault -> UnlockOutcome.CorruptedVault
    UnlockResult.NoPepper -> UnlockOutcome.NoPepper
    UnlockResult.LegacyVaultNoPepper -> UnlockOutcome.LegacyVaultNoPepper
    UnlockResult.Aborted -> UnlockOutcome.Aborted
    UnlockResult.RollbackDetected -> UnlockOutcome.RollbackDetected
    UnlockResult.VaultAlreadyExists -> UnlockOutcome.VaultAlreadyExists
    is UnlockResult.Failure -> UnlockOutcome.Failure(cause)
}
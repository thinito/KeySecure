package com.example.KeySecure.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.KeySecure.KeySecureApp
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
    val vaultCorrupted: Boolean = false
) {
    val isLocked: Boolean get() = lockoutRemainingSec > 0
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
        viewModelScope.launch { refreshLockout() }
        viewModelScope.launch {
            vault.unlocked.collect { if (!it) _state.value = UnlockState() }
        }
    }

    private suspend fun refreshLockout() {
        val pinRemain = if (tracker.isPinLockedOut()) tracker.pinRemainingMs() else 0L
        val phraseRemain = if (tracker.isPhraseLockedOut()) tracker.phraseRemainingMs() else 0L
        val remain = maxOf(pinRemain, phraseRemain)
        if (remain > 0) {
            _state.update { it.copy(lockoutRemainingSec = (remain / 1000).toInt()) }
            startCountdown()
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
            // volta a false quando o lockout expira
            _state.update { it.copy(isProcessing = false, error = null) }
        }
    }

    fun onPinChange(v: String) {
        if (v.length <= SecurityPolicy.MAX_PIN_LENGTH && v.all { it in '0'..'9' })
            _state.update { it.copy(pin = v, error = null) }
    }

    fun onPhraseChange(v: String) =
        _state.update { it.copy(phrase = v, error = null) }

    fun toggleUsePhrase() =
        _state.update { it.copy(usePhrase = !it.usePhrase, error = null) }

    fun submit() {
        if (_state.value.isProcessing || _state.value.isLocked) return
        //  serialize submit para evitar corrida em toque duplo
        submitJob?.cancel()
        submitJob = viewModelScope.launch {
            _state.update { it.copy(isProcessing = true, error = null) }

            val s = _state.value
            val result = withContext(Dispatchers.Default) {
                if (s.usePhrase) {
                    if (tracker.isPhraseLockedOut()) return@withContext UnlockResult.WrongCredential
                    vault.unlockPhrase(s.phrase.toCharArray())
                } else {
                    if (!SecurityPolicy.isValidPin(s.pin)) {
                        return@withContext UnlockResult.WrongCredential
                    }
                    if (tracker.isPinLockedOut()) return@withContext UnlockResult.WrongCredential
                    vault.unlockPin(s.pin.toCharArray())
                }
            }

            when (result) {
                is UnlockResult.Success -> {
                    if (s.usePhrase) tracker.resetPhrase() else tracker.resetPin()
                    _state.update { it.copy(pin = "", phrase = "", error = null, isProcessing = false) }
                }
                is UnlockResult.WrongCredential -> {
                    if (s.usePhrase) tracker.registerPhraseFailure() else tracker.registerPinFailure()
                    _state.update { it.copy(error = "Credencial incorreta", isProcessing = false) }
                    refreshLockout()
                }
                is UnlockResult.NoVault -> {
                    _state.update { it.copy(error = "Nenhum cofre encontrado", isProcessing = false) }
                }
                is UnlockResult.CorruptedVault -> {
                    _state.update { it.copy(error = "Arquivo corrompido", vaultCorrupted = true, isProcessing = false) }
                }
                is UnlockResult.Failure -> {
                    _state.update { it.copy(error = result.cause.message ?: "Erro", isProcessing = false) }
                }
            }
        }
    }
}
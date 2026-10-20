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
    val vaultCorrupted: Boolean = false,
    val legacyVault: Boolean = false,
    val pepperMissing: Boolean = false
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

    private suspend fun refreshLockoutSuspend() {
        val pinRemain = if (tracker.isPinLockedOut()) tracker.pinRemainingMs() else 0L
        val phraseRemain = if (tracker.isPhraseLockedOut()) tracker.phraseRemainingMs() else 0L
        val remainMs = maxOf(pinRemain, phraseRemain)

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
            _state.update { it.copy(error = null) }
        }
    }

    fun onPinChange(value: String) {
        if (value.length <= SecurityPolicy.MAX_PIN_LENGTH && value.all { it in '0'..'9' }) {
            _state.update { it.copy(pin = value, error = null) }
        }
    }

    fun onPhraseChange(value: String) {
        _state.update { it.copy(phrase = value, error = null) }
    }

    fun toggleUsePhrase() {
        _state.update { it.copy(usePhrase = !it.usePhrase, error = null) }
    }

    fun submit() {
        val s = _state.value
        if (s.isProcessing || s.isLocked) return

        submitJob?.cancel()
        submitJob = viewModelScope.launch {
            _state.update { it.copy(isProcessing = true, error = null) }

            val usePhrase = s.usePhrase
            val pinChars = if (usePhrase) null else s.pin.toCharArray()
            val phraseChars = if (usePhrase) s.phrase.toCharArray() else null

            val result: UnlockResult = withContext(Dispatchers.Default) {
                try {
                    if (usePhrase) {
                        if (tracker.isPhraseLockedOut()) UnlockResult.WrongCredential
                        else vault.unlockPhrase(phraseChars!!)
                    } else {
                        if (!SecurityPolicy.isValidPin(s.pin)) UnlockResult.WrongCredential
                        else if (tracker.isPinLockedOut()) UnlockResult.WrongCredential
                        else vault.unlockPin(pinChars!!)
                    }
                } catch (t: Throwable) {
                    UnlockResult.Failure(t)
                }
            }

            when (result) {
                is UnlockResult.Success -> {
                    if (usePhrase) tracker.resetPhrase() else tracker.resetPin()
                    _state.update {
                        it.copy(pin = "", phrase = "", error = null, isProcessing = false)
                    }
                }
                is UnlockResult.WrongCredential -> {
                    if (usePhrase) tracker.registerPhraseFailure() else tracker.registerPinFailure()
                    _state.update {
                        it.copy(error = "Credencial incorreta", isProcessing = false)
                    }
                    refreshLockoutSuspend()
                }
                is UnlockResult.NoVault -> {
                    _state.update {
                        it.copy(error = "Nenhum cofre encontrado", isProcessing = false)
                    }
                }
                is UnlockResult.CorruptedVault -> {
                    _state.update {
                        it.copy(
                            error = "Arquivo corrompido",
                            vaultCorrupted = true,
                            isProcessing = false
                        )
                    }
                }
                is UnlockResult.NoPepper -> {
                    // A chave HMAC do Keystore sumiu (ex.: factory reset).
                    // PIN não é mais verificável. Frase é o caminho de recuperação.
                    _state.update {
                        it.copy(
                            error = "PIN indisponível neste aparelho. Use a frase-chave.",
                            pepperMissing = true,
                            usePhrase = true,
                            isProcessing = false
                        )
                    }
                }
                is UnlockResult.LegacyVaultNoPepper -> {
                    _state.update {
                        it.copy(
                            error = "Cofre antigo (sem proteção de hardware). Use a frase-chave.",
                            legacyVault = true,
                            usePhrase = true,
                            isProcessing = false
                        )
                    }
                }
                is UnlockResult.Failure -> {
                    _state.update {
                        it.copy(
                            error = result.cause.message ?: "Erro inesperado",
                            isProcessing = false
                        )
                    }
                }
            }

            pinChars?.fill('\u0000')
            phraseChars?.fill('\u0000')
        }
    }

    override fun onCleared() {
        super.onCleared()
        countdownJob?.cancel()
        submitJob?.cancel()
    }
}
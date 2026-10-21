package com.example.KeySecure.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.KeySecure.KeySecureApp
import com.example.KeySecure.R
import com.example.KeySecure.UnlockResult
import com.example.KeySecure.data.SecurityPolicy
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

data class SetupState(
    val pin: String = "",
    val confirmPin: String = "",
    val phrase: String = "",
    val confirmPhrase: String = "",
    val error: String? = null,
    val isProcessing: Boolean = false,
    val done: Boolean = false,
    val pendingBiometricEnroll: Boolean = false
) {
    val canSubmit: Boolean
        get() = !isProcessing && !done &&
                pin.isNotEmpty() && confirmPin.isNotEmpty() &&
                phrase.isNotEmpty() && confirmPhrase.isNotEmpty()
}

class SetupViewModel(app: Application) : AndroidViewModel(app) {

    private val keyApp = app as KeySecureApp
    private val vault = keyApp.vault

    private val _state = MutableStateFlow(SetupState())
    val state = _state.asStateFlow()

    fun onPinChange(v: String) {
        if (v.length > SecurityPolicy.MAX_PIN_LENGTH || !v.all { it in '0'..'9' }) return
        _state.update { it.copy(pin = v, error = null) }
    }

    fun onConfirmPinChange(v: String) {
        if (v.length > SecurityPolicy.MAX_PIN_LENGTH || !v.all { it in '0'..'9' }) return
        _state.update { it.copy(confirmPin = v, error = null) }
    }

    fun onPhraseChange(v: String) {
        if (v.length > SecurityPolicy.MAX_PASSPHRASE_LENGTH) return
        _state.update { it.copy(phrase = v, error = null) }
    }

    fun onConfirmPhraseChange(v: String) {
        if (v.length > SecurityPolicy.MAX_PASSPHRASE_LENGTH) return
        _state.update { it.copy(confirmPhrase = v, error = null) }
    }

    fun create() {
        val s = _state.value
        if (s.isProcessing || s.done) return
        val app = getApplication<Application>()

        validatePin(s.pin, s.confirmPin, app)?.let {
            _state.update { st -> st.copy(error = it) }; return
        }
        validatePhrase(s.phrase, s.confirmPhrase, app)?.let {
            _state.update { st -> st.copy(error = it) }; return
        }

        viewModelScope.launch {
            _state.update { it.copy(isProcessing = true, error = null) }
            val result = withContext(Dispatchers.Default) {
                vault.create(s.pin.toCharArray(), s.phrase.toCharArray())
            }
            when (result) {
                is UnlockResult.Success -> {
                    val available = BiometricHelper.isAvailable(getApplication())
                    // ✅ Reset completo: descarta as Strings de PIN/frase do estado.
                    _state.value = SetupState(
                        done = true,
                        isProcessing = false,
                        pendingBiometricEnroll = available
                    )
                }
                is UnlockResult.Aborted -> {
                    _state.value = SetupState() // lock() concorrente; RootScreen reage
                }
                is UnlockResult.WrongCredential -> {
                    _state.update {
                        it.copy(error = app.getString(R.string.error_pin_weak), isProcessing = false)
                    }
                }
                else -> {
                    _state.update {
                        it.copy(error = app.getString(R.string.error_create_failed), isProcessing = false)
                    }
                }
            }
        }
    }

    fun finishBiometricEnroll() {
        _state.update { it.copy(pendingBiometricEnroll = false) }
    }

    private fun validatePin(pin: String, confirm: String, app: Application): String? {
        if (pin.length !in SecurityPolicy.MIN_PIN_LENGTH..SecurityPolicy.MAX_PIN_LENGTH) {
            return app.getString(
                R.string.error_pin_format,
                SecurityPolicy.MIN_PIN_LENGTH, SecurityPolicy.MAX_PIN_LENGTH
            )
        }
        if (!SecurityPolicy.isStrongPin(pin)) return app.getString(R.string.error_pin_weak)
        if (pin != confirm) return app.getString(R.string.error_pin_mismatch)
        return null
    }

    private fun validatePhrase(phrase: String, confirm: String, app: Application): String? {
        if (phrase.length < SecurityPolicy.MIN_PASSPHRASE_LENGTH) {
            return app.getString(R.string.error_phrase_format, SecurityPolicy.MIN_PASSPHRASE_LENGTH)
        }
        if (phrase.length > SecurityPolicy.MAX_PASSPHRASE_LENGTH) {
            return app.getString(R.string.error_phrase_too_long, SecurityPolicy.MAX_PASSPHRASE_LENGTH)
        }
        if (!SecurityPolicy.isStrongPassphrase(phrase)) return app.getString(R.string.error_phrase_weak)
        if (phrase != confirm) return app.getString(R.string.error_phrase_mismatch)
        return null
    }
}
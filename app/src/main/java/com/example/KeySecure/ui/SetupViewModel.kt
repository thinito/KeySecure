package com.example.KeySecure.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.KeySecure.KeySecureApp
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
    val phrase: String = "",
    val error: String? = null,
    val isProcessing: Boolean = false,
    val done: Boolean = false
)

class SetupViewModel(app: Application) : AndroidViewModel(app) {

    private val vault = (app as KeySecureApp).vault

    private val _state = MutableStateFlow(SetupState())
    val state = _state.asStateFlow()

    fun onPinChange(v: String) {
        if (v.length <= SecurityPolicy.MAX_PIN_LENGTH && v.all { it in '0'..'9' })
            _state.update { it.copy(pin = v, error = null) }
    }

    fun onPhraseChange(v: String) = _state.update { it.copy(phrase = v, error = null) }

    fun create() {
        val s = _state.value
        if (!SecurityPolicy.isValidPin(s.pin)) {
            _state.update { it.copy(error = "PIN fraco ou inválido") }; return
        }
        if (!SecurityPolicy.isValidPassphrase(s.phrase)) {
            _state.update { it.copy(error = "Frase muito fraca") }; return
        }
        viewModelScope.launch {
            _state.update { it.copy(isProcessing = true, error = null) }
            val result = withContext(Dispatchers.Default) {
                vault.create(s.pin.toCharArray(), s.phrase.toCharArray())
            }
            when (result) {
                is UnlockResult.Success ->
                    _state.update { it.copy(done = true, isProcessing = false) }
                else ->
                    _state.update { it.copy(error = "Falha ao criar cofre", isProcessing = false) }
            }
        }
    }
}
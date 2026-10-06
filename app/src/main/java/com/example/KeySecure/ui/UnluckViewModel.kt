package com.example.KeySecure.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.KeySecure.Vault
import com.example.KeySecure.data.AttemptTracker
import com.example.KeySecure.data.SecurityPolicy
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.io.File

data class UnlockState(
    val pin: String = "",
    val error: String? = null,
    val isLocked: Boolean = false,
    val unlocked: Boolean = false
)

class UnlockViewModel(app: Application) : AndroidViewModel(app) {

    private val vault = Vault(File(app.filesDir, "vault.json"))
    private val tracker = AttemptTracker(app)

    private val _state = MutableStateFlow(UnlockState())
    val state = _state.asStateFlow()

    init {
        viewModelScope.launch {
            if (tracker.isLockedOut()) {
                val secs = tracker.remainingLockoutMs() / 1000
                _state.update { it.copy(isLocked = true, error = "Bloqueado por ${secs}s") }
            }
        }
    }

    fun onPinChange(value: String) {
        if (value.length <= SecurityPolicy.MAX_PIN_LENGTH && value.all { it.isDigit() }) {
            _state.update { it.copy(pin = value, error = null) }
        }
    }

    fun submit() {
        val current = _state.value
        if (!SecurityPolicy.isValidPin(current.pin)) {
            _state.update { it.copy(error = "PIN deve ter ${SecurityPolicy.MIN_PIN_LENGTH}+ dígitos") }
            return
        }
        viewModelScope.launch {
            if (tracker.isLockedOut()) {
                val secs = tracker.remainingLockoutMs() / 1000
                _state.update { it.copy(isLocked = true, error = "Bloqueado. Tente em ${secs}s") }
                return@launch
            }
            val ok = vault.unlockPin(current.pin.toCharArray())
            if (ok) {
                tracker.reset()
                _state.update { it.copy(unlocked = true, error = null) }
            } else {
                tracker.registerFailure()
                _state.update { it.copy(pin = "", error = "PIN incorreto") }
            }
        }
    }
}
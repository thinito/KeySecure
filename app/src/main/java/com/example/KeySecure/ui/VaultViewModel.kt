package com.example.KeySecure.ui

import android.app.Application
import android.content.Context
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.KeySecure.KeySecureApp
import com.example.KeySecure.data.VaultEntry
import com.example.KeySecure.util.ClipboardUtil
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

class VaultViewModel(app: Application) : AndroidViewModel(app) {

    private val vault = (app as KeySecureApp).vault

    private val _entries = MutableStateFlow<List<VaultEntry>>(emptyList())
    val entries: StateFlow<List<VaultEntry>> = _entries.asStateFlow()

    /** Última mensagem de erro de escrita; consumida pela UI via `clearError()`. */
    private val _lastError = MutableStateFlow<String?>(null)
    val lastError: StateFlow<String?> = _lastError.asStateFlow()

    init {
        viewModelScope.launch {
            vault.unlocked.collect { if (it) refresh() else _entries.value = emptyList() }
        }
    }

    fun refresh() {
        _entries.value = vault.getEntries()
    }

    fun add(name: String, user: String, pass: String): Result<VaultEntry> {
        val result = vault.addEntry(name, user, pass)
        handle(result)
        return result
    }

    fun update(id: String, name: String, user: String, pass: String): Result<Unit> {
        val result = vault.updateEntry(id, name, user, pass)
        handle(result)
        return result
    }

    fun delete(id: String): Result<Unit> {
        val result = vault.deleteEntry(id)
        handle(result)
        return result
    }

    fun copyPassword(ctx: Context, value: String) {
        ClipboardUtil.copySensitive(ctx, "senha", value)
    }

    fun lock() = vault.lock()

    fun clearError() {
        _lastError.value = null
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
package com.example.KeySecure.ui

import android.app.Application
import android.content.Context
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.KeySecure.KeySecureApp
import com.example.KeySecure.data.VaultEntry
import com.example.KeySecure.util.ClipboardUtil
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

class VaultViewModel(app: Application) : AndroidViewModel(app) {

    private val vault = (app as KeySecureApp).vault

    private val _entries = MutableStateFlow<List<VaultEntry>>(emptyList())
    val entries = _entries.asStateFlow()

    init {
        viewModelScope.launch {
            vault.unlocked.collect { if (it) refresh() else _entries.value = emptyList() }
        }
    }

    fun refresh() { _entries.value = vault.getEntries() }
    fun add(e: VaultEntry) { vault.addEntry(e); refresh() }
    fun update(o: VaultEntry, n: VaultEntry) { vault.updateEntry(o, n); refresh() }
    fun delete(e: VaultEntry) { vault.deleteEntry(e); refresh() }

    fun copyPassword(ctx: Context, v: String) {
        ClipboardUtil.copySensitive(ctx, "senha", v)
    }

    fun lock() = vault.lock()

    /** apenas o VaultViewModel mantém lock em onStop via MainActivity. */
}
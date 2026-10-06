package com.example.KeySecure.ui

import android.app.Application
import android.content.Context
import androidx.lifecycle.AndroidViewModel
import com.example.KeySecure.Vault
import com.example.KeySecure.util.ClipboardUtil
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import java.io.File

class VaultViewModel(app: Application) : AndroidViewModel(app) {

    private val vault = Vault(File(app.filesDir, "vault.json"))
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    fun copyPassword(context: Context, value: String) {
        ClipboardUtil.copySensitive(context, "senha", value, scope)
    }

    fun lock() = vault.lock()
}
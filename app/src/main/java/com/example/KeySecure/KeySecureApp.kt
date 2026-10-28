package com.example.KeySecure

import android.app.Application
import com.example.KeySecure.crypto.KeystoreManager
import com.example.KeySecure.data.AttemptTracker
import com.example.KeySecure.data.VaultRepository
import com.example.KeySecure.util.CrashLogger
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import java.io.File

class KeySecureApp : Application() {

    private val appScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    val keystore: KeystoreManager by lazy { KeystoreManager() }

    private val vaultInstance: Vault by lazy {
        Vault(File(filesDir, "vault.json"), keystore)
    }

    val vaultRepository: VaultRepository by lazy {
        VaultRepository(vaultInstance, appScope)
    }

    val vault: Vault get() = vaultInstance

    val attemptTracker: AttemptTracker by lazy { AttemptTracker(this) }

    override fun onCreate() {
        // ANTES de qualquer outra inicialização — captura crashes em
        // qualquer parte do app, inclusive no resto deste onCreate.
        CrashLogger.install(this)

        super.onCreate()
    }
}
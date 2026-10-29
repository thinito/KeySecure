package com.example.KeySecure

import android.app.Application
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import com.example.KeySecure.crypto.KeystoreManager
import com.example.KeySecure.data.AttemptTracker
import com.example.KeySecure.data.LockPreferences
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

    val lockPreferences: LockPreferences by lazy { LockPreferences(this) }

    override fun onCreate() {
        super.onCreate()

        CrashLogger.install(this)

        // ✅ Aplica o timeout salvo e registra o observer de processo.
        LockTimeoutHandler.setTimeout(lockPreferences.getTimeout())
        ProcessLifecycleOwner.get().lifecycle.addObserver(
            LockLifecycleObserver(this)
        )
    }
}

/**
 * Observa o ciclo de vida do **processo** (não de activities individuais).
 * `ProcessLifecycleOwner`:
 *  - Dispara ON_START quando a primeira activity visível inicia.
 *  - Dispara ON_STOP quando **todas** as activities param — ignorando
 *    rotação de tela e mudanças de configuração.
 */
private class LockLifecycleObserver(
    private val app: KeySecureApp
) : DefaultLifecycleObserver {

    override fun onStart(owner: LifecycleOwner) {
        LockTimeoutHandler.onAppForegrounded(app.vault)
    }

    override fun onStop(owner: LifecycleOwner) {
        LockTimeoutHandler.onAppBackgrounded(app.vault)
    }
}
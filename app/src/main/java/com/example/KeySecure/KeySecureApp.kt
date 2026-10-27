package com.example.KeySecure

import android.app.Application
import com.example.KeySecure.crypto.KeystoreManager
import com.example.KeySecure.data.AttemptTracker
import com.example.KeySecure.data.VaultRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import java.io.File

/**
 * Application com as instâncias únicas (singleton) do projeto.
 *
 *  - [vaultRepository]: fachada única usada por ViewModels e UI.
 *  - [vault]: instância bruta do [Vault], mantida para uso interno
 *    (LockTimeoutHandler e testes).
 *  - [keystore]: Android Keystore.
 *  - [attemptTracker]: tracker de tentativas.
 */
class KeySecureApp : Application() {

    /** Escopo de vida longa para o `stateIn` do repositório. */
    private val appScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    val keystore: KeystoreManager by lazy { KeystoreManager() }

    /** Única instância do [Vault]. Nunca instancie outro em lugar nenhum. */
    private val vaultInstance: Vault by lazy {
        Vault(File(filesDir, "vault.json"), keystore)
    }

    /**
     * ✅ Fachada única — use esta nas ViewModels e na UI.
     * Compartilha o mesmo [Vault] que [vault], então `lock()` em um é
     * visível no outro.
     */
    val vaultRepository: VaultRepository by lazy {
        VaultRepository(vaultInstance, appScope)
    }

    /** Acesso controlado à instância bruta (LockTimeoutHandler, testes). */
    val vault: Vault get() = vaultInstance

    val attemptTracker: AttemptTracker by lazy { AttemptTracker(this) }

    override fun onCreate() {
        super.onCreate()
        // Nada de I/O pesado aqui — os `lazy` inicializam sob demanda.
    }
}
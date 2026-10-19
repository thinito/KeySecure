package com.example.KeySecure

import android.app.Application
import com.example.KeySecure.crypto.KeystoreManager
import com.example.KeySecure.data.AttemptTracker
import java.io.File

class KeySecureApp : Application() {

    val vault: Vault by lazy {
        Vault(File(filesDir, "vault.json"), KeystoreManager())
    }

    val attemptTracker: AttemptTracker by lazy { AttemptTracker(this) }

    override fun onCreate() {
        super.onCreate()
        // Nada de I/O pesado aqui.
        // Não instancie Vault/AttemptTracker neste ponto:
        // eles são inicializados sob demanda (lazy).
    }
}
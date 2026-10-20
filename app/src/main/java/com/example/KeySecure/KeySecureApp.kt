package com.example.KeySecure

import android.app.Application
import com.example.KeySecure.crypto.KeystoreManager
import com.example.KeySecure.data.AttemptTracker
import java.io.File

class KeySecureApp : Application() {

    val keystore: KeystoreManager by lazy { KeystoreManager() }

    val vault: Vault by lazy {
        Vault(File(filesDir, "vault.json"), keystore)
    }

    val attemptTracker: AttemptTracker by lazy { AttemptTracker(this) }

    override fun onCreate() {
        super.onCreate()
    }
}
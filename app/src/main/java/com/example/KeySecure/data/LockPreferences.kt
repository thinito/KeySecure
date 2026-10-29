package com.example.KeySecure.data

import android.content.Context

/**
 * Persiste a preferência de timeout de auto-lock do usuário.
 *
 * Usa `SharedPreferences` (não `DataStore`) porque é um único par
 * chave-valor sem reatividade complexa. O `LockTimeoutHandler` mantém
 * o valor em memória e é atualizado via `setTimeout()` quando o usuário
 * muda a preferência.
 */
class LockPreferences(context: Context) {

    private val prefs = context.applicationContext
        .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    fun getTimeout(): SecurityPolicy.LockTimeout =
        SecurityPolicy.LockTimeout.fromName(prefs.getString(KEY_TIMEOUT, null))

    fun setTimeout(timeout: SecurityPolicy.LockTimeout) {
        prefs.edit().putString(KEY_TIMEOUT, timeout.name).apply()
    }

    private companion object {
        const val PREFS_NAME = "keysecure_lock"
        const val KEY_TIMEOUT = "timeout"
    }
}
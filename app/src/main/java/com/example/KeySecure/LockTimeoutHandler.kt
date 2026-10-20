package com.example.KeySecure

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.SystemClock
import com.example.KeySecure.data.SecurityPolicy

/**
 * Gerencia o auto-lock do cofre em três frentes:
 *
 *  1. `stoppedAt` (elapsedRealtime) marcado em `onStop`. Em `onStart`,
 *     se `elapsedRealtime() - stoppedAt >= LOCK_TIMEOUT_MS`, tranca.
 *     Usa `elapsedRealtime` (inclui sono profundo) em vez de
 *     `uptimeMillis` (usado por `Handler.postDelayed`).
 *
 *  2. `BroadcastReceiver` de `ACTION_SCREEN_OFF`, registrado enquanto
 *     a activity está iniciada. Tranca imediatamente ao apagar a tela.
 *
 *  3. `onActivityDestroyed` (chamado com `isFinishing == true`) tranca
 *     explicitamente, garantindo que a saída do app não deixe a chave
 *     em memória.
 *
 * Compatível com um único `MainActivity` (estado é singleton).
 */
object LockTimeoutHandler {

    private var stoppedAt: Long = 0L

    private var appContext: Context? = null
    private var screenOffReceiver: BroadcastReceiver? = null

    // ------------------------------------------------------------------
    // Ciclo de vida
    // ------------------------------------------------------------------

    /** Chamado em `onStart`. Registra receiver e tranca se o tempo passou. */
    fun onActivityStarted(context: Context, vault: Vault) {
        val now = SystemClock.elapsedRealtime()
        val elapsed = if (stoppedAt > 0L && now >= stoppedAt) {
            now - stoppedAt
        } else {
            0L
        }
        stoppedAt = 0L

        if (elapsed >= SecurityPolicy.LOCK_TIMEOUT_MS) {
            vault.lock()
        }

        registerScreenOff(context.applicationContext, vault)
    }

    /** Chamado em `onStop`. Marca `stoppedAt` e para de receber screen-off. */
    fun onActivityStopped(vault: Vault) {
        stoppedAt = SystemClock.elapsedRealtime()
        unregisterScreenOff()
    }

    /** Chamado em `onDestroy` quando `isFinishing`. Tranca e limpa. */
    fun onActivityDestroyed(vault: Vault) {
        unregisterScreenOff()
        vault.lock()
    }

    // ------------------------------------------------------------------
    // Screen-off receiver
    // ------------------------------------------------------------------

    private fun registerScreenOff(context: Context, vault: Vault) {
        if (screenOffReceiver != null) return
        appContext = context
        screenOffReceiver = object : BroadcastReceiver() {
            override fun onReceive(c: Context?, intent: Intent?) {
                if (intent?.action == Intent.ACTION_SCREEN_OFF) {
                    vault.lock()
                }
            }
        }
        val filter = IntentFilter(Intent.ACTION_SCREEN_OFF)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context.registerReceiver(
                screenOffReceiver,
                filter,
                Context.RECEIVER_NOT_EXPORTED
            )
        } else {
            @Suppress("UnspecifiedRegisterReceiverFlag")
            context.registerReceiver(screenOffReceiver, filter)
        }
    }

    private fun unregisterScreenOff() {
        val ctx = appContext ?: return
        val r = screenOffReceiver ?: return
        runCatching { ctx.unregisterReceiver(r) }
        screenOffReceiver = null
        appContext = null
    }
}
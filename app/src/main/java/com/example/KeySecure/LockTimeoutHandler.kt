package com.example.KeySecure

import android.os.Handler
import android.os.Looper
import com.example.KeySecure.data.SecurityPolicy

/**
 * Agenda o travamento do cofre após um período em segundo plano.
 *
 * Uso:
 *   - MainActivity.onStop()  -> scheduleLock(vault)
 *   - MainActivity.onStart() -> cancel()
 *
 * lock configurável em vez de imediato.
 */
object LockTimeoutHandler {

    private val handler = Handler(Looper.getMainLooper())
    private var pending: Runnable? = null

    /**
     * Agenda o lock do cofre após [SecurityPolicy.LOCK_TIMEOUT_MS].
     * Chamadas repetidas substituem o agendamento anterior.
     */
    fun scheduleLock(vault: Vault) {
        cancel()
        val r = Runnable { vault.lock() }
        pending = r
        handler.postDelayed(r, SecurityPolicy.LOCK_TIMEOUT_MS)
    }

    /**
     * Cancela um lock pendente.
     * Deve ser chamado quando o app volta ao primeiro plano.
     */
    fun cancel() {
        pending?.let { handler.removeCallbacks(it) }
        pending = null
    }

    /**
     * Executa o lock imediatamente e cancela qualquer agendamento.
     * Útil para ser chamado em ACTION_SCREEN_OFF ou logout manual.
     */
    fun lockNow(vault: Vault) {
        cancel()
        vault.lock()
    }
}
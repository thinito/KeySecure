package com.example.KeySecure

import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import com.example.KeySecure.data.SecurityPolicy.LockTimeout

/**
 * Auto-lock configurável do cofre quando o app vai para segundo plano.
 *
 * Estratégia:
 *  - `onAppBackgrounded` registra `backgroundedAt` (elapsedRealtime) e
 *    agenda um `Runnable` no `Handler` para `timeout.millis`.
 *  - `onAppForegrounded` cancela o Handler e, se `elapsedRealtime -
 *    backgroundedAt >= timeout`, tranca imediatamente (caso o device
 *    tenha dormido e o Handler não tenha disparado).
 *  - `timeout.millis == 0` (IMMEDIATE): tranca sem agendar.
 *
 * Por que combinar Handler + elapsedRealtime:
 *  - `Handler.postDelayed` usa `uptimeMillis`, que congela em sono profundo.
 *  - `elapsedRealtime` avança inclusive em sono profundo.
 *  - O Handler garante o lock **enquanto o app está em background** (processo
 *    vivo, UI oculta).
 *  - A checagem em `onAppForegrounded` cobre o caso "device dormiu e o
 *    Handler não disparou, mas o tempo real passou".
 *
 * Integração: `KeySecureApp.onCreate` registra um `DefaultLifecycleObserver`
 * em `ProcessLifecycleOwner` que chama `onAppBackgrounded`/`onAppForegrounded`.
 * `ProcessLifecycleOwner` já ignora `isChangingConfigurations`, então rotação
 * de tela não dispara lock.
 */
object LockTimeoutHandler {

    private val handler = Handler(Looper.getMainLooper())
    private var pending: Runnable? = null

    @Volatile private var timeoutMillis: Long = LockTimeout.DEFAULT.millis
    @Volatile private var backgroundedAt: Long = 0L

    /** Atualiza o timeout. Tem efeito no próximo `onAppBackgrounded`. */
    fun setTimeout(timeout: LockTimeout) {
        timeoutMillis = timeout.millis
    }

    /** Chamado quando o app vai para segundo plano (ProcessLifecycleOwner ON_STOP). */
    fun onAppBackgrounded(vault: Vault) {
        cancel()
        backgroundedAt = SystemClock.elapsedRealtime()

        if (timeoutMillis == 0L) {
            vault.lock()
            return
        }

        val r = Runnable {
            if (backgroundedAt > 0L &&
                SystemClock.elapsedRealtime() - backgroundedAt >= timeoutMillis
            ) {
                vault.lock()
            }
        }
        pending = r
        handler.postDelayed(r, timeoutMillis)
    }

    /** Chamado quando o app volta ao primeiro plano (ProcessLifecycleOwner ON_START). */
    fun onAppForegrounded(vault: Vault) {
        val bg = backgroundedAt
        backgroundedAt = 0L
        cancel()

        // Se o device dormiu durante o background, o Handler não disparou
        // (uptimeMillis congelou), mas elapsedRealtime avançou. Tranca agora.
        if (bg > 0L && SystemClock.elapsedRealtime() - bg >= timeoutMillis) {
            vault.lock()
        }
    }

    fun cancel() {
        pending?.let { handler.removeCallbacks(it) }
        pending = null
    }
}
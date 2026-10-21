package com.example.KeySecure.data

import android.content.Context
import android.os.SystemClock
import android.provider.Settings
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.first

private val Context.attemptStore by preferencesDataStore("attempts")

/**
 * Rastreia tentativas falhas com:
 *
 *  - **Contador ÚNICO** compartilhado entre PIN e frase-chave. Alternar
 *    entre os dois não dobra as tentativas antes do lockout.
 *  - **Lockout único** (`lock_elapsed_v3` + `lock_wall_v3` + `boot_count_v3`).
 *  - **Backoff exponencial** com shift capped em 10 (`coerceAtMost(10)`),
 *    evitando overflow de Long e wraparound de shift.
 *
 * Compatibilidade: `isPinLockedOut()`, `registerPhraseFailure()` etc.
 * continuam existindo como aliases para o `UnlockViewModel` atual.
 *
 * ⚠️ As chaves foram renomeadas para `_v3` porque a semântica mudou
 *    (shared). Um lockout pendente da versão anterior (`_v2`) é ignorado.
 *    O usuário ganha, no pior caso, um único ciclo extra de tentativas.
 */
class AttemptTracker(private val context: Context) {

    private val KEY_FAILED = intPreferencesKey("failed_v3")
    private val KEY_LOCK_ELAPSED = longPreferencesKey("lock_elapsed_v3")
    private val KEY_LOCK_WALL = longPreferencesKey("lock_wall_v3")
    private val KEY_BOOT_COUNT = intPreferencesKey("boot_count_v3")

    // ------------------------------------------------------------------
    // Detecção de boot
    // ------------------------------------------------------------------
    private fun bootCount(): Int = try {
        Settings.Global.getInt(
            context.contentResolver,
            Settings.Global.BOOT_COUNT,
            UNKNOWN_BOOT
        )
    } catch (t: Throwable) {
        UNKNOWN_BOOT
    }

    /**
     * Mesmo boot: usa `elapsedRealtime` (imune a mudança de hora).
     * Boot diferente ou BOOT_COUNT indisponível: usa wall clock.
     */
    private fun computeRemaining(
        lockElapsed: Long,
        lockWall: Long,
        storedBoot: Int
    ): Long {
        if (lockElapsed == 0L && lockWall == 0L) return 0L
        val currentBoot = bootCount()
        val sameBoot = storedBoot != UNKNOWN_BOOT && currentBoot == storedBoot
        val remaining = if (sameBoot) {
            lockElapsed - SystemClock.elapsedRealtime()
        } else {
            lockWall - System.currentTimeMillis()
        }
        return remaining.coerceAtLeast(0L)
    }

    /**
     * Delay do lockout com backoff exponencial.
     *
     * `shift` é limitado a 10: `30_000L shl 10 = 30_720_000` ms (~8,5h),
     * que o `coerceAtMost(MAX_LOCKOUT_MS)` corta para 30 min. Valores
     * maiores de shift estourariam Long (`30_000L shl 49` vira negativo)
     * e fariam o lockout desaparecer.
     */
    private fun lockoutDelay(failed: Int): Long {
        if (failed < SecurityPolicy.MAX_FAILED_ATTEMPTS) return 0L
        val level = failed - SecurityPolicy.MAX_FAILED_ATTEMPTS
        val shift = level.coerceAtMost(10)
        return (SecurityPolicy.BASE_LOCKOUT_MS shl shift)
            .coerceAtMost(SecurityPolicy.MAX_LOCKOUT_MS)
    }

    // ------------------------------------------------------------------
    // API unificada
    // ------------------------------------------------------------------
    suspend fun isLockedOut(): Boolean {
        val p = context.attemptStore.data.first()
        return computeRemaining(
            p[KEY_LOCK_ELAPSED] ?: 0L,
            p[KEY_LOCK_WALL] ?: 0L,
            p[KEY_BOOT_COUNT] ?: UNKNOWN_BOOT
        ) > 0L
    }

    suspend fun remainingMs(): Long {
        val p = context.attemptStore.data.first()
        return computeRemaining(
            p[KEY_LOCK_ELAPSED] ?: 0L,
            p[KEY_LOCK_WALL] ?: 0L,
            p[KEY_BOOT_COUNT] ?: UNKNOWN_BOOT
        )
    }

    /**
     * Registra uma falha (de PIN OU de frase — o contador é o mesmo).
     * Quando atinge [SecurityPolicy.MAX_FAILED_ATTEMPTS], ativa o lockout
     * com backoff exponencial proporcional ao excesso.
     */
    suspend fun registerFailure() {
        context.attemptStore.edit { prefs ->
            val failed = (prefs[KEY_FAILED] ?: 0) + 1
            prefs[KEY_FAILED] = failed

            val delay = lockoutDelay(failed)
            if (delay > 0L) {
                val nowElapsed = SystemClock.elapsedRealtime()
                val nowWall = System.currentTimeMillis()
                prefs[KEY_LOCK_ELAPSED] = nowElapsed + delay
                prefs[KEY_LOCK_WALL] = nowWall + delay
                prefs[KEY_BOOT_COUNT] = bootCount()
            }
        }
    }

    /** Zera contador e lockout. Chamado após destrancar com sucesso. */
    suspend fun reset() {
        context.attemptStore.edit { it.clear() }
    }

    // ------------------------------------------------------------------
    // Aliases de compatibilidade (mesmo estado interno)
    // ------------------------------------------------------------------
    suspend fun isPinLockedOut(): Boolean = isLockedOut()
    suspend fun isPhraseLockedOut(): Boolean = isLockedOut()
    suspend fun pinRemainingMs(): Long = remainingMs()
    suspend fun phraseRemainingMs(): Long = remainingMs()
    suspend fun registerPinFailure() = registerFailure()
    suspend fun registerPhraseFailure() = registerFailure()
    suspend fun resetPin() = reset()
    suspend fun resetPhrase() = reset()

    companion object {
        private const val UNKNOWN_BOOT = -1
    }
}
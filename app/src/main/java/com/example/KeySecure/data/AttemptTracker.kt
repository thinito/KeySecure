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
 * Rastreia tentativas falhas e lockout, com defesa contra:
 *   (a) mudança do relógio do sistema (wall clock);
 *   (b) reinício do aparelho.
 *
 * Estratégia:
 *   - Ao registrar uma falha que dispara lockout, grava:
 *       • lockUntilElapsed = SystemClock.elapsedRealtime() + delay
 *       • lockUntilWall    = System.currentTimeMillis()  + delay
 *       • bootCount        = Settings.Global.BOOT_COUNT
 *   - Ao consultar, se o BOOT_COUNT ainda é o mesmo (mesmo boot):
 *       remaining = lockUntilElapsed - elapsedRealtime()
 *     Caso contrário (reboot ou BOOT_COUNT indisponível):
 *       remaining = lockUntilWall - currentTimeMillis()
 *
 *   - NUNCA zera contadores no reboot. Apenas resetPin()/resetPhrase()/reset()
 *     zeram. O `failed_pin`/`failed_phrase` persistem entre sessões e reinícios.
 */
class AttemptTracker(private val context: Context) {

    private val KEY_FAILED_PIN = intPreferencesKey("failed_pin_v2")
    private val KEY_FAILED_PHRASE = intPreferencesKey("failed_phrase_v2")

    private val KEY_LOCK_PIN_ELAPSED = longPreferencesKey("lock_pin_elapsed")
    private val KEY_LOCK_PIN_WALL = longPreferencesKey("lock_pin_wall")
    private val KEY_LOCK_PHRASE_ELAPSED = longPreferencesKey("lock_phrase_elapsed")
    private val KEY_LOCK_PHRASE_WALL = longPreferencesKey("lock_phrase_wall")

    private val KEY_BOOT_COUNT = intPreferencesKey("boot_count")

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
        // Alguns fabricantes restringem a leitura. Cai no fallback por wall.
        UNKNOWN_BOOT
    }

    /**
     * Retorna quanto falta (em ms) para o lockout expirar, ou 0 se não há lockout.
     *
     * - Mesmo boot: usa elapsed (imune a mudança de hora).
     * - Boot diferente ou BOOT_COUNT desconhecido: usa wall (imune a reboot).
     */
    private fun remainingMs(
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

    /** Calcula o delay do lockout com backoff exponencial, limitado a MAX_LOCKOUT_MS. */
    private fun lockoutDelay(failed: Int): Long {
        if (failed < SecurityPolicy.MAX_FAILED_ATTEMPTS) return 0L
        // Cap do shift para evitar overflow do Long.shl (que wrapa em shift >= 64)
        val shift = (failed - SecurityPolicy.MAX_FAILED_ATTEMPTS).coerceIn(0, 20)
        return (SecurityPolicy.BASE_LOCKOUT_MS shl shift)
            .coerceAtMost(SecurityPolicy.MAX_LOCKOUT_MS)
    }

    // ------------------------------------------------------------------
    // PIN
    // ------------------------------------------------------------------
    suspend fun isPinLockedOut(): Boolean {
        val p = context.attemptStore.data.first()
        return remainingMs(
            p[KEY_LOCK_PIN_ELAPSED] ?: 0L,
            p[KEY_LOCK_PIN_WALL] ?: 0L,
            p[KEY_BOOT_COUNT] ?: UNKNOWN_BOOT
        ) > 0L
    }

    suspend fun pinRemainingMs(): Long {
        val p = context.attemptStore.data.first()
        return remainingMs(
            p[KEY_LOCK_PIN_ELAPSED] ?: 0L,
            p[KEY_LOCK_PIN_WALL] ?: 0L,
            p[KEY_BOOT_COUNT] ?: UNKNOWN_BOOT
        )
    }

    suspend fun registerPinFailure() {
        context.attemptStore.edit { prefs ->
            val failed = (prefs[KEY_FAILED_PIN] ?: 0) + 1
            prefs[KEY_FAILED_PIN] = failed

            val delay = lockoutDelay(failed)
            if (delay > 0L) {
                val nowElapsed = SystemClock.elapsedRealtime()
                val nowWall = System.currentTimeMillis()
                prefs[KEY_LOCK_PIN_ELAPSED] = nowElapsed + delay
                prefs[KEY_LOCK_PIN_WALL] = nowWall + delay
                prefs[KEY_BOOT_COUNT] = bootCount()
            }
        }
    }

    suspend fun resetPin() {
        context.attemptStore.edit {
            it[KEY_FAILED_PIN] = 0
            it[KEY_LOCK_PIN_ELAPSED] = 0L
            it[KEY_LOCK_PIN_WALL] = 0L
        }
    }

    // ------------------------------------------------------------------
    // Frase-chave
    // ------------------------------------------------------------------
    suspend fun isPhraseLockedOut(): Boolean {
        val p = context.attemptStore.data.first()
        return remainingMs(
            p[KEY_LOCK_PHRASE_ELAPSED] ?: 0L,
            p[KEY_LOCK_PHRASE_WALL] ?: 0L,
            p[KEY_BOOT_COUNT] ?: UNKNOWN_BOOT
        ) > 0L
    }

    suspend fun phraseRemainingMs(): Long {
        val p = context.attemptStore.data.first()
        return remainingMs(
            p[KEY_LOCK_PHRASE_ELAPSED] ?: 0L,
            p[KEY_LOCK_PHRASE_WALL] ?: 0L,
            p[KEY_BOOT_COUNT] ?: UNKNOWN_BOOT
        )
    }

    suspend fun registerPhraseFailure() {
        context.attemptStore.edit { prefs ->
            val failed = (prefs[KEY_FAILED_PHRASE] ?: 0) + 1
            prefs[KEY_FAILED_PHRASE] = failed

            val delay = lockoutDelay(failed)
            if (delay > 0L) {
                val nowElapsed = SystemClock.elapsedRealtime()
                val nowWall = System.currentTimeMillis()
                prefs[KEY_LOCK_PHRASE_ELAPSED] = nowElapsed + delay
                prefs[KEY_LOCK_PHRASE_WALL] = nowWall + delay
                prefs[KEY_BOOT_COUNT] = bootCount()
            }
        }
    }

    suspend fun resetPhrase() {
        context.attemptStore.edit {
            it[KEY_FAILED_PHRASE] = 0
            it[KEY_LOCK_PHRASE_ELAPSED] = 0L
            it[KEY_LOCK_PHRASE_WALL] = 0L
        }
    }

    // ------------------------------------------------------------------
    // Reset completo (usado em logout/apagar cofre)
    // ------------------------------------------------------------------
    suspend fun reset() {
        context.attemptStore.edit { it.clear() }
    }

    companion object {
        /** Valor retornado por Settings.Global.BOOT_COUNT quando não é possível ler. */
        private const val UNKNOWN_BOOT = -1
    }
}
package com.example.KeySecure.data

import android.content.Context
import android.os.SystemClock
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.first

private val Context.attemptStore by preferencesDataStore("attempts")

/**
 * usa SystemClock.elapsedRealtime() + boot marker (resistente a mudança de hora).
 * Aplica-se tanto a PIN quanto a frase.
 * Backoff exponencial limitado por MAX_LOCKOUT_MS.
 */
class AttemptTracker(private val context: Context) {

    private val KEY_FAILED_PIN = intPreferencesKey("failed_pin")
    private val KEY_FAILED_PHRASE = intPreferencesKey("failed_phrase")
    private val KEY_LOCK_UNTIL_PIN = longPreferencesKey("lock_until_pin")
    private val KEY_LOCK_UNTIL_PHRASE = longPreferencesKey("lock_until_phrase")

    private fun now(): Long = SystemClock.elapsedRealtime()

    /** Detecta se o dispositivo reiniciou desde a última leitura. */
    private suspend fun bootMarker(): Long =
        context.attemptStore.data.first()[longPreferencesKey("boot_marker")]
            ?: (System.currentTimeMillis() - now())

    private suspend fun ensureBootMarker() {
        context.attemptStore.edit { prefs ->
            val stored = prefs[longPreferencesKey("boot_marker")] ?: 0L
            val current = System.currentTimeMillis() - now()
            // Se a diferença for > 5s, houve reboot: zera contadores
            if (stored == 0L || kotlin.math.abs(current - stored) > 5_000L) {
                prefs[longPreferencesKey("boot_marker")] = current
                prefs[KEY_FAILED_PIN] = 0
                prefs[KEY_FAILED_PHRASE] = 0
                prefs[KEY_LOCK_UNTIL_PIN] = 0L
                prefs[KEY_LOCK_UNTIL_PHRASE] = 0L
            }
        }
    }

    // ---------- PIN ----------
    suspend fun isPinLockedOut(): Boolean {
        ensureBootMarker()
        val p = context.attemptStore.data.first()
        val until = p[KEY_LOCK_UNTIL_PIN] ?: 0L
        return until > 0L && now() < until
    }

    suspend fun pinRemainingMs(): Long {
        val p = context.attemptStore.data.first()
        return ((p[KEY_LOCK_UNTIL_PIN] ?: 0L) - now()).coerceAtLeast(0L)
    }

    suspend fun registerPinFailure() {
        ensureBootMarker()
        context.attemptStore.edit { prefs ->
            val f = (prefs[KEY_FAILED_PIN] ?: 0) + 1
            if (f >= SecurityPolicy.MAX_FAILED_ATTEMPTS) {
                // Backoff exponencial: 30s, 60s, 120s, ... cap MAX_LOCKOUT_MS
                val level = f - SecurityPolicy.MAX_FAILED_ATTEMPTS
                val delay = (SecurityPolicy.BASE_LOCKOUT_MS shl level)
                    .coerceAtMost(SecurityPolicy.MAX_LOCKOUT_MS)
                prefs[KEY_LOCK_UNTIL_PIN] = now() + delay
                prefs[KEY_FAILED_PIN] = f
            } else {
                prefs[KEY_FAILED_PIN] = f
            }
        }
    }

    suspend fun resetPin() {
        context.attemptStore.edit {
            it[KEY_FAILED_PIN] = 0
            it[KEY_LOCK_UNTIL_PIN] = 0L
        }
    }

    // ---------- Frase ----------
    suspend fun isPhraseLockedOut(): Boolean {
        val p = context.attemptStore.data.first()
        val until = p[KEY_LOCK_UNTIL_PHRASE] ?: 0L
        return until > 0L && now() < until
    }

    suspend fun phraseRemainingMs(): Long {
        val p = context.attemptStore.data.first()
        return ((p[KEY_LOCK_UNTIL_PHRASE] ?: 0L) - now()).coerceAtLeast(0L)
    }

    suspend fun registerPhraseFailure() {
        ensureBootMarker()
        context.attemptStore.edit { prefs ->
            val f = (prefs[KEY_FAILED_PHRASE] ?: 0) + 1
            if (f >= SecurityPolicy.MAX_FAILED_ATTEMPTS) {
                val level = f - SecurityPolicy.MAX_FAILED_ATTEMPTS
                val delay = (SecurityPolicy.BASE_LOCKOUT_MS shl level)
                    .coerceAtMost(SecurityPolicy.MAX_LOCKOUT_MS)
                prefs[KEY_LOCK_UNTIL_PHRASE] = now() + delay
                prefs[KEY_FAILED_PHRASE] = f
            } else {
                prefs[KEY_FAILED_PHRASE] = f
            }
        }
    }

    suspend fun resetPhrase() {
        context.attemptStore.edit {
            it[KEY_FAILED_PHRASE] = 0
            it[KEY_LOCK_UNTIL_PHRASE] = 0L
        }
    }

    suspend fun reset() {
        context.attemptStore.edit { it.clear() }
    }
}
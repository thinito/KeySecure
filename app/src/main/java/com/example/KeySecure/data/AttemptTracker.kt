import android.content.Context
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.first

private val Context.attemptStore by preferencesDataStore("attempts")

class AttemptTracker(private val context: Context) {

    private val KEY_FAILED = intPreferencesKey("failed_attempts")
    private val KEY_LOCK_UNTIL = longPreferencesKey("lock_until")

    suspend fun isLockedOut(): Boolean {
        val prefs = context.attemptStore.data.first()
        val lockUntil = prefs[KEY_LOCK_UNTIL] ?: 0L
        return System.currentTimeMillis() < lockUntil
    }

    suspend fun remainingLockoutMs(): Long {
        val prefs = context.attemptStore.data.first()
        val lockUntil = prefs[KEY_LOCK_UNTIL] ?: 0L
        return (lockUntil - System.currentTimeMillis()).coerceAtLeast(0L)
    }

    suspend fun registerFailure() {
        context.attemptStore.edit { prefs ->
            val failed = (prefs[KEY_FAILED] ?: 0) + 1
            prefs[KEY_FAILED] = failed
            if (failed >= SecurityPolicy.MAX_FAILED_ATTEMPTS) {
                prefs[KEY_LOCK_UNTIL] =
                    System.currentTimeMillis() + SecurityPolicy.LOCKOUT_DURATION_MS
                prefs[KEY_FAILED] = 0
            }
        }
    }

    suspend fun reset() {
        context.attemptStore.edit { it.clear() }
    }
}
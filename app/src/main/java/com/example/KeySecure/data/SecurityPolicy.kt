package com.example.KeySecure.data

object SecurityPolicy {

    // ---- Limites de CRIAÇÃO (podem ser endurecidos) ----
    const val MIN_PIN_LENGTH = 8
    const val MAX_PIN_LENGTH = 12
    const val MIN_PASSPHRASE_LENGTH = 12
    const val MAX_PASSPHRASE_LENGTH = 128

    // ---- Limites HISTÓRICOS de DESBLOQUEIO (NUNCA aumente) ----
    private const val HISTORICAL_MIN_PIN_LENGTH = 6
    private const val HISTORICAL_MAX_PIN_LENGTH = 12
    private const val HISTORICAL_MIN_PASSPHRASE_LENGTH = 12
    private const val HISTORICAL_MAX_PASSPHRASE_LENGTH = 1024

    const val MAX_FAILED_ATTEMPTS = 5
    const val BASE_LOCKOUT_MS = 30_000L
    const val MAX_LOCKOUT_MS = 30 * 60_000L

    const val PBKDF2_ITERATIONS = 600_000
    const val MIN_ACCEPTED_ITERATIONS = 100_000
    const val MAX_ACCEPTED_ITERATIONS = 2_000_000

    const val ARGON2_MEMORY_KIB = 19_456
    const val ARGON2_ITERATIONS = 2
    const val ARGON2_PARALLELISM = 1

    const val SALT_LENGTH_BYTES = 16
    const val IV_LENGTH_BYTES = 12
    const val GCM_TAG_BITS = 128

    // ------------------------------------------------------------------
    // Timeout de auto-lock configurável
    // ------------------------------------------------------------------
    /**
     * Prazo para o cofre se auto-trancar quando o app vai para segundo plano.
     *
     * - `IMMEDIATE`: trava assim que o app perde foco (mais seguro, menos cômodo).
     * - `THIRTY_SECONDS` (default): preserva o comportamento original do app.
     * - `ONE_MINUTE`: janela maior para copiar senha e colar em outro app.
     *
     * O valor é persistido via [LockPreferences] e aplicado em
     * [com.example.KeySecure.LockTimeoutHandler].
     */
    enum class LockTimeout(val millis: Long) {
        IMMEDIATE(0L),
        FIFTEEN_SECONDS(15_000L),
        THIRTY_SECONDS(30_000L),
        ONE_MINUTE(60_000L);

        companion object {
            val DEFAULT = THIRTY_SECONDS

            fun fromName(name: String?): LockTimeout =
                entries.firstOrNull { it.name == name } ?: DEFAULT
        }
    }

    // ---- Estimador zxcvbn ----
    private const val MIN_PASSPHRASE_ENTROPY_BITS = 60.0
    private const val MIN_GUESSES_LOG10 = MIN_PASSPHRASE_ENTROPY_BITS / 3.321928

    private val zxcvbn by lazy { com.nulabinc.zxcvbn.Zxcvbn() }

    // ------------------------------------------------------------------
    // PIN
    // ------------------------------------------------------------------
    fun isWellFormedPin(pin: CharArray): Boolean =
        pin.size in HISTORICAL_MIN_PIN_LENGTH..HISTORICAL_MAX_PIN_LENGTH &&
            pin.all { it in '0'..'9' }

    fun isWellFormedPin(pin: String): Boolean =
        pin.length in HISTORICAL_MIN_PIN_LENGTH..HISTORICAL_MAX_PIN_LENGTH &&
            pin.all { it in '0'..'9' }

    fun isStrongPin(pin: CharArray): Boolean {
        if (pin.size !in MIN_PIN_LENGTH..MAX_PIN_LENGTH) return false
        if (!pin.all { it in '0'..'9' }) return false
        return !isTrivialPin(pin)
    }

    fun isStrongPin(pin: String): Boolean {
        if (pin.length !in MIN_PIN_LENGTH..MAX_PIN_LENGTH) return false
        if (!pin.all { it in '0'..'9' }) return false
        return !isTrivialPin(pin)
    }

    private fun isTrivialPin(pin: CharArray): Boolean {
        if (pin.size < 2) return false
        if (pin.all { it == pin[0] }) return true
        var asc = true; var desc = true
        for (i in 1 until pin.size) {
            if (pin[i] != pin[i - 1] + 1) asc = false
            if (pin[i] != pin[i - 1] - 1) desc = false
            if (!asc && !desc) return false
        }
        return asc || desc
    }

    private fun isTrivialPin(pin: String): Boolean {
        if (pin.length < 2) return false
        if (pin.all { it == pin[0] }) return true
        var asc = true; var desc = true
        for (i in 1 until pin.length) {
            if (pin[i] != pin[i - 1] + 1) asc = false
            if (pin[i] != pin[i - 1] - 1) desc = false
            if (!asc && !desc) return false
        }
        return asc || desc
    }

    // ------------------------------------------------------------------
    // Frase
    // ------------------------------------------------------------------
    fun normalizePassphrase(raw: CharArray): String =
        java.text.Normalizer.normalize(String(raw), java.text.Normalizer.Form.NFKC)

    fun normalizePassphrase(raw: String): String =
        java.text.Normalizer.normalize(raw, java.text.Normalizer.Form.NFKC)

    fun isWellFormedPassphrase(raw: String): Boolean =
        raw.length in HISTORICAL_MIN_PASSPHRASE_LENGTH..HISTORICAL_MAX_PASSPHRASE_LENGTH

    fun isStrongPassphrase(raw: String): Boolean {
        val phrase = normalizePassphrase(raw)
        if (phrase.length !in MIN_PASSPHRASE_LENGTH..MAX_PASSPHRASE_LENGTH) return false
        val result = zxcvbn.measure(phrase)
        if (result.guessesLog10 < MIN_GUESSES_LOG10) return false
        if (result.score < 3) return false
        return true
    }

    fun validateIterations(iter: Int): Boolean =
        iter in MIN_ACCEPTED_ITERATIONS..MAX_ACCEPTED_ITERATIONS
}
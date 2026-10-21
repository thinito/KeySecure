package com.example.KeySecure.data

object SecurityPolicy {

    // ---- Limites de CRIAÇÃO (podem ser endurecidos) ----
    const val MIN_PIN_LENGTH = 6
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
    const val LOCK_TIMEOUT_MS = 30_000L
    const val MAX_LOCKOUT_MS = 30 * 60_000L

    const val PBKDF2_ITERATIONS = 600_000
    const val MIN_ACCEPTED_ITERATIONS = 100_000
    const val MAX_ACCEPTED_ITERATIONS = 2_000_000

    const val SALT_LENGTH_BYTES = 16
    const val IV_LENGTH_BYTES = 12
    const val GCM_TAG_BITS = 128

    // ------------------------------------------------------------------
    // PIN — CharArray (desbloqueio sem String imutável)
    // ------------------------------------------------------------------
    fun isWellFormedPin(pin: CharArray): Boolean =
        pin.size in HISTORICAL_MIN_PIN_LENGTH..HISTORICAL_MAX_PIN_LENGTH &&
                pin.all { it in '0'..'9' }

    fun isStrongPin(pin: CharArray): Boolean {
        if (pin.size !in MIN_PIN_LENGTH..MAX_PIN_LENGTH) return false
        if (!pin.all { it in '0'..'9' }) return false
        return !isTrivialPin(pin)
    }

    // ------------------------------------------------------------------
    // PIN — String (UI / testes)
    // ------------------------------------------------------------------
    fun isWellFormedPin(pin: String): Boolean =
        pin.length in HISTORICAL_MIN_PIN_LENGTH..HISTORICAL_MAX_PIN_LENGTH &&
                pin.all { it in '0'..'9' }

    fun isStrongPin(pin: String): Boolean {
        if (pin.length !in MIN_PIN_LENGTH..MAX_PIN_LENGTH) return false
        if (!pin.all { it in '0'..'9' }) return false
        return !isTrivialPin(pin)
    }

    private fun isTrivialPin(pin: CharArray): Boolean {
        if (pin.size < 2) return false
        if (pin.all { it == pin[0] }) return true
        var asc = true
        var desc = true
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
        var asc = true
        var desc = true
        for (i in 1 until pin.length) {
            if (pin[i] != pin[i - 1] + 1) asc = false
            if (pin[i] != pin[i - 1] - 1) desc = false
            if (!asc && !desc) return false
        }
        return asc || desc
    }

    // ------------------------------------------------------------------
    // Frase — NFKC exige String (limitação da JVM)
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
        if (phrase.all { it == phrase[0] }) return false
        if (phrase.lowercase() in COMMON_PASSPHRASES) return false
        val classes = listOf(
            phrase.any { it.isLowerCase() },
            phrase.any { it.isUpperCase() },
            phrase.any { it.isDigit() },
            phrase.any { !it.isLetterOrDigit() }
        ).count { it }
        return classes >= 2
    }

    private val COMMON_PASSPHRASES = setOf(
        "password", "123456789012", "qwertyuiopas",
        "aaaaaaaaaaaa", "senha1234567", "frasefrasefrase"
    )

    fun validateIterations(iter: Int): Boolean =
        iter in MIN_ACCEPTED_ITERATIONS..MAX_ACCEPTED_ITERATIONS

    // ------------------------------------------------------------------
    // Aliases de compatibilidade (@Deprecated).
    // Preservados para não quebrar código/testes antigos.
    // ------------------------------------------------------------------
    @Deprecated(
        "Use isStrongPin (criação) ou isWellFormedPin (desbloqueio)",
        ReplaceWith("isStrongPin(pin)")
    )
    fun isValidPin(pin: String): Boolean = isStrongPin(pin)

    @Deprecated(
        "Use isStrongPassphrase (criação) ou isWellFormedPassphrase (desbloqueio)",
        ReplaceWith("isStrongPassphrase(raw)")
    )
    fun isValidPassphrase(raw: String): Boolean = isStrongPassphrase(raw)
}
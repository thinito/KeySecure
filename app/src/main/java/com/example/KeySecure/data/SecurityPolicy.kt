package com.example.KeySecure.data

import com.nulabinc.zxcvbn.Zxcvbn

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
    const val LOCK_TIMEOUT_MS = 30_000L
    const val MAX_LOCKOUT_MS = 30 * 60_000L

    const val PBKDF2_ITERATIONS = 600_000
    const val MIN_ACCEPTED_ITERATIONS = 100_000
    const val MAX_ACCEPTED_ITERATIONS = 2_000_000

    // Parâmetros do Argon2id (OWASP: 19 MiB, t=2, p=1)
    const val ARGON2_MEMORY_KIB = 19_456   // 19 MiB
    const val ARGON2_ITERATIONS = 2
    const val ARGON2_PARALLELISM = 1

    const val SALT_LENGTH_BYTES = 16
    const val IV_LENGTH_BYTES = 12
    const val GCM_TAG_BITS = 128

    // Estimador zxcvbn (singleton — a criação da instância é custosa)
    private val zxcvbn by lazy { Zxcvbn() }

    /**
     * Mínimo de entropia para a frase-chave, em bits.
     * 60 bits ≈ 10^18 tentativas — inviável offline mesmo com hardware dedicado.
     * O zxcvbn retorna `guessesLog10`; log10(2^60) ≈ 18.06, então exigimos >= 18.
     */
    private const val MIN_PASSPHRASE_ENTROPY_BITS = 60.0
    private const val MIN_GUESSES_LOG10 = MIN_PASSPHRASE_ENTROPY_BITS / 3.321928 // ≈ 18.06

    // ------------------------------------------------------------------
    // PIN
    // ------------------------------------------------------------------
    fun isWellFormedPin(pin: CharArray): Boolean =
        pin.size in HISTORICAL_MIN_PIN_LENGTH..HISTORICAL_MAX_PIN_LENGTH &&
            pin.all { it in '0'..'9' }

    fun isStrongPin(pin: CharArray): Boolean {
        if (pin.size !in MIN_PIN_LENGTH..MAX_PIN_LENGTH) return false
        if (!pin.all { it in '0'..'9' }) return false
        return !isTrivialPin(pin)
    }

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
    // Frase-chave
    // ------------------------------------------------------------------
    fun normalizePassphrase(raw: CharArray): String =
        java.text.Normalizer.normalize(String(raw), java.text.Normalizer.Form.NFKC)

    fun normalizePassphrase(raw: String): String =
        java.text.Normalizer.normalize(raw, java.text.Normalizer.Form.NFKC)

    /**
     * Formato de frase para DESBLOQUEIO — só comprimento, sem avaliar força.
     * Um vault antigo com frase fraca ainda precisa abrir.
     */
    fun isWellFormedPassphrase(raw: String): Boolean =
        raw.length in HISTORICAL_MIN_PASSPHRASE_LENGTH..HISTORICAL_MAX_PASSPHRASE_LENGTH

    /**
     * Frase FORTE para CRIAÇÃO.
     *
     * Usa zxcvbn:
     *  - pontuação 0..4 (0 = trivial, 4 = muito forte);
     *  - `guessesLog10` estima o log10 do número de tentativas.
     *
     * Exigimos:
     *  1. comprimento entre MIN e MAX;
     *  2. `guessesLog10 >= 18` (≈ 60 bits de entropia);
     *  3. pontuação >= 3 (defesa em profundidade).
     */
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
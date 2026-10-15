package com.example.KeySecure.data

object SecurityPolicy {

    const val MIN_PIN_LENGTH = 6
    const val MAX_PIN_LENGTH = 12
    const val MIN_PASSPHRASE_LENGTH = 12
    const val MAX_PASSPHRASE_LENGTH = 128

    const val MAX_FAILED_ATTEMPTS = 5
    const val BASE_LOCKOUT_MS = 30_000L          // 30s
    const val MAX_LOCKOUT_MS = 30 * 60_000L      // teto de 30min (backoff exponencial)

    const val PBKDF2_ITERATIONS = 600_000
    const val MIN_ACCEPTED_ITERATIONS = 100_000
    const val MAX_ACCEPTED_ITERATIONS = 2_000_000

    const val SALT_LENGTH_BYTES = 16
    const val IV_LENGTH_BYTES = 12
    const val GCM_TAG_BITS = 128

    const val LOCK_TIMEOUT_MS = 30_000L

    /**
     * apenas dígitos ASCII '0'..'9'. Bloqueia PINs triviais.
     */
    fun isValidPin(pin: String): Boolean {
        if (pin.length !in MIN_PIN_LENGTH..MAX_PIN_LENGTH) return false
        if (!pin.all { it in '0'..'9' }) return false
        return !isTrivialPin(pin)
    }

    private fun isTrivialPin(pin: String): Boolean {
        if (pin.all { it == pin[0] }) return true // 000000, 111111
        // Sequências crescentes/decrescentes
        val digits = pin.map { it - '0' }
        val asc = digits.zipWithNext().all { (a, b) -> b == a + 1 }
        val desc = digits.zipWithNext().all { (a, b) -> b == a - 1 }
        return asc || desc
    }

    /**
     *normaliza NFKC antes da validação e exige entropia mínima.
     */
    fun normalizePassphrase(raw: String): String {
        return java.text.Normalizer.normalize(raw, java.text.Normalizer.Form.NFKC)
    }

    fun isValidPassphrase(raw: String): Boolean {
        val phrase = normalizePassphrase(raw)
        if (phrase.length !in MIN_PASSPHRASE_LENGTH..MAX_PASSPHRASE_LENGTH) return false
        if (phrase.all { it == phrase[0] }) return false
        if (phrase.toLowerCase() in COMMON_PASSPHRASES) return false
        // Mínimo de 3 classes de caracteres
        val classes = listOf(
            phrase.any { it.isLowerCase() },
            phrase.any { it.isUpperCase() },
            phrase.any { it.isDigit() },
            phrase.any { !it.isLetterOrDigit() }
        ).count { it }
        return classes >= 2 // 2 de 4 classes (permite frases longas só de letras/espaços)
    }

    private val COMMON_PASSPHRASES = setOf(
        "password", "123456789012", "qwertyuiopas",
        "aaaaaaaaaaaa", "senha1234567", "frasefrasefrase"
    )

    fun validateIterations(iter: Int): Boolean =
        iter in MIN_ACCEPTED_ITERATIONS..MAX_ACCEPTED_ITERATIONS
}
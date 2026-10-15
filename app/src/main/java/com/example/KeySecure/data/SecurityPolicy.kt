package com.example.KeySecure.data

/**
 * Política central de segurança do cofre.
 * Não alterar valores sem revisar docs/SECURITY.md.
 */
object SecurityPolicy {
    const val MIN_PIN_LENGTH = 6
    const val MAX_PIN_LENGTH = 12
    const val MIN_PASSPHRASE_LENGTH = 12

    const val MAX_FAILED_ATTEMPTS = 5
    const val LOCKOUT_DURATION_MS = 5 * 60 * 1000L // 5 minutos

    const val PBKDF2_ITERATIONS = 600_000
    const val SALT_LENGTH_BYTES = 16
    const val IV_LENGTH_BYTES = 12
    const val GCM_TAG_BITS = 128

    fun isValidPin(pin: String): Boolean =
        pin.length in MIN_PIN_LENGTH..MAX_PIN_LENGTH && pin.all { it.isDigit() }

    fun isValidPassphrase(phrase: String): Boolean =
        phrase.length >= MIN_PASSPHRASE_LENGTH
}
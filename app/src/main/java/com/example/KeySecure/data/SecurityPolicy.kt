object SecurityPolicy {
    const val MIN_PIN_LENGTH = 8
    const val MAX_FAILED_ATTEMPTS = 5
    const val LOCKOUT_DURATION_MS = 5 * 60 * 1000L // 5 minutos

    fun isValidPin(pin: String): Boolean =
        pin.length >= MIN_PIN_LENGTH && pin.all { it.isDigit() }

    fun isValidPassphrase(phrase: String): Boolean =
        phrase.length >= 12
}
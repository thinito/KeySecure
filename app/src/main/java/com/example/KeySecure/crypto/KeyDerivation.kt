object KeyDerivation {
    // OWASP 2023: 600_000 iterações para PBKDF2-HMAC-SHA256
    const val ITERATIONS_V1 = 210_000   // valor antigo (vaults existentes)
    const val ITERATIONS_V2 = 600_000   // novo padrão
    const val KEY_LENGTH = 256
    const val SALT_LENGTH = 16

    fun deriveKey(
        password: CharArray,
        salt: ByteArray,
        iterations: Int = ITERATIONS_V2
    ): SecretKey {
        val spec = PBEKeySpec(password, salt, iterations, KEY_LENGTH)
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val keyBytes = factory.generateSecret(spec).encoded
        val key = SecretKeySpec(keyBytes, "AES")
        // limpa buffers
        spec.clearPassword()
        keyBytes.fill(0)
        return key
    }

    fun randomSalt(): ByteArray = ByteArray(SALT_LENGTH).also {
        SecureRandom().nextBytes(it)
    }
}   
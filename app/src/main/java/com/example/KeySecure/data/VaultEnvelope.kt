package com.example.KeySecure.data

import kotlinx.serialization.Serializable

/**
 * Envelope em disco.
 *
 * Versão 5:
 *  - PIN e frase com pepper (HMAC do Keystore).
 *  - `counter` monotônico para rollback.
 *  - AAD prefixado por papel.
 *
 * `kdfPhrase` indica o algoritmo usado no embrulho da frase:
 *  - `"PBKDF2"` (padrão em v5): PBKDF2-HMAC-SHA256.
 *  - `"ARGON2ID"` (novo): Argon2id com parâmetros de `SecurityPolicy`.
 *
 * Vaults v5 antigos têm `kdfPhrase = "PBKDF2"`; o upgrade converte para
 * Argon2id.
 */
@Serializable
data class VaultEnvelope(
    val version: Int = CURRENT_VERSION,
    val counter: Long = 0L,
    val iterPin: Int,
    val iterPhrase: Int,
    val saltPin: String,
    val saltPhrase: String,
    val wrappedKeyPin: String,
    val wrappedKeyPhrase: String,
    val wrappedKeyKeystore: String? = null,
    val data: String,
    val kdfPhrase: String = "PBKDF2"
) {
    companion object {
        const val CURRENT_VERSION = 5
        const val MIN_SUPPORTED_VERSION = 3
        const val KDF_PBKDF2 = "PBKDF2"
        const val KDF_ARGON2ID = "ARGON2ID"
    }
}

@Serializable
data class VaultEntry(
    val id: String = "",
    val name: String,
    val user: String,
    val pass: String,
    val createdAt: Long = 0L,
    val updatedAt: Long = 0L
)
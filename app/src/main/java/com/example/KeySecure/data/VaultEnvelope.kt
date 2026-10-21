package com.example.KeySecure.data

import kotlinx.serialization.Serializable

/**
 * Envelope em disco.
 *
 * Mudanças de formato (v4):
 *  - `counter`: contador monotônico, incrementado em cada gravação.
 *    Incluído no AAD do campo `data`, então adulterar o contador quebra
 *    a decifra. Serve também como base para detecção de rollback via
 *    arquivo `.meta`.
 *  - AAD agora é prefixado com o papel (`pin|`, `phrase|`, `data|`,
 *    `keystore|`), evitando reuso entre contextos.
 *
 * `version` deve ser escrito **explicitamente** (`encodeDefaults = true`),
 * para que arquivos antigos nunca sejam lidos com um default novo.
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
    val data: String
) {
    companion object {
        const val CURRENT_VERSION = 4
        const val MIN_SUPPORTED_VERSION = 3
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
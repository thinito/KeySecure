package com.example.KeySecure.data

import kotlinx.serialization.Serializable

/**
 * Envelope em disco.
 *
 * Versão 5 (atual):
 *  - PIN e frase-chave têm wrappers **ambos** endurecidos com HMAC do
 *    Keystore (pepper). Sem o aparelho, nenhuma das duas credenciais
 *    pode ser testada offline.
 *  - `counter` monotônico para detecção de rollback (best-effort).
 *  - AAD prefixado por papel (`pin|`, `phrase|`, `data|`, `keystore|`).
 *
 * Versões anteriores:
 *  - v4: pepper só no PIN; frase em PBKDF2 puro.
 *  - v3: pré-pepper, apenas frase abre.
 *
 * `encodeDefaults = true` garante que `version` e `counter` sejam
 * sempre escritos, mesmo quando iguais ao default.
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
        const val CURRENT_VERSION = 5
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
package com.example.KeySecure.data

import kotlinx.serialization.Serializable

/**
 * Envelope em disco. O `version` continua 4 porque o header/AAD não
 * mudou nesta rodada — a migração de entradas é interna ao campo `data`.
 *
 * Campos `id`, `createdAt`, `updatedAt` de [VaultEntry] usam default
 * (`""` e `0L`) para permitir desserializar vaults antigos. A migração
 * de fato acontece em `Vault.migrateEntriesIfNeeded` antes de publicar
 * o estado destrancado.
 */
@Serializable
data class VaultEnvelope(
    val version: Int = 4,
    val iterPin: Int,
    val iterPhrase: Int,
    val saltPin: String,
    val saltPhrase: String,
    val wrappedKeyPin: String,
    val wrappedKeyPhrase: String,
    val wrappedKeyKeystore: String? = null,
    val data: String
)

/**
 * Entrada do cofre.
 *
 * - `id`: UUID estável. Entradas antigas (sem id) recebem um na primeira
 *   vez que o cofre é aberto.
 * - `createdAt`/`updatedAt`: timestamps em wall clock (ms desde epoch).
 * - `name`, `user`, `pass`: os dados em si.
 *
 * A UI usa `id` como chave estável da lista e as operações CRUD usam
 * `id` como identificador — não `==` de dados.
 */
@Serializable
data class VaultEntry(
    val id: String = "",
    val name: String,
    val user: String,
    val pass: String,
    val createdAt: Long = 0L,
    val updatedAt: Long = 0L
)
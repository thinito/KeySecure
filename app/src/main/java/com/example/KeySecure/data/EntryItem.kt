package com.example.KeySecure.data

/**
 * Versão "sem segredo" de [VaultEntry] para a UI.
 *
 * Não contém `pass`. A senha vive apenas dentro do [Vault] e é lida
 * sob demanda (`getEntryPasswordSnapshot`) quando o usuário copia ou
 * edita. Dessa forma, o `StateFlow` do `VaultViewModel` nunca carrega
 * segredos em memória além do necessário.
 */
data class EntryItem(
    val id: String,
    val name: String,
    val user: String
)
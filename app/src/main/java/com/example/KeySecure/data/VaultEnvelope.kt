package com.example.KeySecure.data

import kotlinx.serialization.Serializable

/**
 * iterações separadas por wrapper (iterPin, iterPhrase).
 * wrapper adicional com Android Keystore (wrappedKeyKeystore).
 * AAD derivado dos campos do header protege contra rollback/adulteração.
 */
@Serializable
data class VaultEnvelope(
    val version: Int = 3,
    val iterPin: Int,
    val iterPhrase: Int,
    val saltPin: String,
    val saltPhrase: String,
    val wrappedKeyPin: String,
    val wrappedKeyPhrase: String,
    val wrappedKeyKeystore: String? = null,  // pode ser null se o dispositivo não suporta biometria
    val data: String
)

@Serializable
data class VaultEntry(
    val name: String,
    val user: String,
    val pass: String
)
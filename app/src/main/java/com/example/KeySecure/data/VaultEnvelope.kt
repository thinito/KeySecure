package com.example.KeySecure.data

import kotlinx.serialization.Serializable

@Serializable
data class VaultEnvelope(
    val version: Int = 2,
    val kdfIterations: Int,
    val saltPin: String,
    val saltPhrase: String,
    val wrappedKeyPin: String,
    val wrappedKeyPhrase: String,
    val entries: List<VaultEntry>
)

@Serializable
data class VaultEntry(
    val name: String,
    val user: String,
    val pass: String
)
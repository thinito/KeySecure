package com.example.KeySecure.crypto

import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

class VaultCrypto {
    private var keyBytes: ByteArray? = null

    fun setKey(bytes: ByteArray) { lock(); keyBytes = bytes.copyOf() }

    fun lock() {
        keyBytes?.fill(0)
        keyBytes = null
    }

    private fun key(): SecretKey =
        SecretKeySpec(keyBytes ?: error("Vault trancado"), "AES")
}
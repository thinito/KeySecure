package com.example.KeySecure.crypto

import javax.crypto.SecretKey

/**
 * Abstração do Android Keystore.
 * Permite substituir por um fake em testes unitários (JVM).
 */
interface IKeystore {
    fun hasKey(): Boolean
    fun createKey()
    fun getKey(): SecretKey
    fun deleteKey()
}
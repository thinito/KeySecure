package com.example.KeySecure.crypto

import javax.crypto.SecretKey

/**
 * Abstração do Android Keystore.
 *
 * Há dois tipos de chave:
 *  - `*Key()/getKey()/deleteKey()` — chave biométrica, exige autenticação.
 *  - `*PepperKey()` — chave HMAC de "pimenta", NÃO exige autenticação,
 *    não exportável. Usada para endurecer a derivação do PIN.
 */
interface IKeystore {

    // --- Chave biométrica (exige autenticação) ---
    fun hasKey(): Boolean
    fun createKey()
    fun getKey(): SecretKey
    fun deleteKey()

    // --- Pepper HMAC (sem autenticação, não exportável) ---
    fun hasPepperKey(): Boolean
    fun createPepperKey()

    /** HMAC-SHA256(pepper_key, data). */
    fun computePepperHmac(data: ByteArray): ByteArray

    fun deletePepperKey()
}
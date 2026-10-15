package com.example.KeySecure.util

import java.util.Base64

/** Base64 padrão da JVM, funciona em testes unitários (sem android.util.Base64). */
fun ByteArray.toBase64(): String = Base64.getEncoder().encodeToString(this)
fun String.base64(): ByteArray = Base64.getDecoder().decode(this)
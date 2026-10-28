package com.example.KeySecure.util

import android.util.Log as AndroidLog

/**
 * Wrapper que escreve no logcat **e** no [CrashLogger].
 *
 * Use nos pontos onde um erro precisa ser diagnosticável pelo usuário
 * (ex.: `catch` de operações de I/O, falhas de criptografia). Para logs
 * rotineiros de debug, use `AndroidLog` direto — não polui o arquivo.
 *
 * ⚠️ Nunca passe segredos (senhas, PIN, frases) para estas funções.
 */
object SafeLog {

    fun e(tag: String, message: String, throwable: Throwable? = null) {
        AndroidLog.e(tag, message, throwable)
        CrashLogger.e(tag, message, throwable)
    }

    fun w(tag: String, message: String, throwable: Throwable? = null) {
        AndroidLog.w(tag, message, throwable)
        CrashLogger.w(tag, message, throwable)
    }

    fun i(tag: String, message: String) {
        AndroidLog.i(tag, message)
        CrashLogger.i(tag, message)
    }

    fun d(tag: String, message: String) {
        AndroidLog.d(tag, message)
        CrashLogger.d(tag, message)
    }
}
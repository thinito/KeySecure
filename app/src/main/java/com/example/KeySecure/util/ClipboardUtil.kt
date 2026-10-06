package com.example.KeySecure.util

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import androidx.core.content.getSystemService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * Copia valores sensíveis para o clipboard e os apaga após 30 segundos.
 */
object ClipboardUtil {

    private const val CLEAR_DELAY_MS = 30_000L
    private var clearJob: Job? = null

    fun copySensitive(
        context: Context,
        label: String,
        value: String,
        scope: CoroutineScope
    ) {
        val cm = context.getSystemService<ClipboardManager>() ?: return
        cm.setPrimaryClip(ClipData.newPlainText(label, value))

        clearJob?.cancel()
        clearJob = scope.launch {
            delay(CLEAR_DELAY_MS)
            val current = cm.primaryClip
            if (current != null &&
                current.itemCount > 0 &&
                current.getItemAt(0).text?.toString() == value
            ) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    cm.clearPrimaryClip()
                } else {
                    @Suppress("DEPRECATION")
                    cm.setPrimaryClip(ClipData.newPlainText("", ""))
                }
            }
        }
    }

    /** Limpa o clipboard imediatamente (ex.: onStop do app). */
    fun clearNow(context: Context) {
        clearJob?.cancel()
        val cm = context.getSystemService<ClipboardManager>() ?: return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            cm.clearPrimaryClip()
        } else {
            @Suppress("DEPRECATION")
            cm.setPrimaryClip(ClipData.newPlainText("", ""))
        }
    }
}
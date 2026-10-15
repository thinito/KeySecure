package com.example.KeySecure.util

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.PersistableBundle
import androidx.core.content.getSystemService

/**
 * NÃO limpa em onStop (evita apagar a senha antes do usuário colar).
 * Marca o clip como sensível (API 33+) e agenda limpeza via Handler no processo.
 * A limpeza após 30s é best-effort: se o processo morrer, o clip permanece.
 */
object ClipboardUtil {

    private const val CLEAR_DELAY_MS = 30_000L

    fun copySensitive(context: Context, label: String, value: String) {
        val cm = context.getSystemService<ClipboardManager>() ?: return
        val clip = ClipData.newPlainText(label, value)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val extras = PersistableBundle().apply {
                putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
            }
            clip.description.extras = extras
        }
        cm.setPrimaryClip(clip)
        scheduleClear(cm, value)
    }

    private fun scheduleClear(cm: ClipboardManager, value: String) {
        android.os.Handler(android.os.Looper.getMainLooper()).postDelayed({
            val cur = cm.primaryClip
            if (cur != null && cur.itemCount > 0 &&
                cur.getItemAt(0).text?.toString() == value
            ) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    cm.clearPrimaryClip()
                } else {
                    @Suppress("DEPRECATION")
                    cm.setPrimaryClip(ClipData.newPlainText("", ""))
                }
            }
        }, CLEAR_DELAY_MS)
    }
}
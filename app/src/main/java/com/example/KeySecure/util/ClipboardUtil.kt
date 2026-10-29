package com.example.KeySecure.util

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.PersistableBundle
import androidx.core.content.getSystemService
import androidx.work.Data
import androidx.work.ExistingWorkPolicy
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.Worker
import androidx.work.WorkerParameters
import java.security.SecureRandom
import java.util.concurrent.TimeUnit

private const val CLEAR_DELAY_SECONDS = 30L
private const val WORK_NAME = "clipboard_clear"
private const val KEY_NONCE = "nonce"
private const val KEY_IS_SENSITIVE_LEGACY = "android.content.extra.IS_SENSITIVE"

private val nonceRandom = SecureRandom()

/**
 * Copia senhas para o clipboard e agenda limpeza em 30 s via WorkManager.
 *
 * Segurança do nonce:
 *  - Um nonce aleatório de 128 bits é gerado por `SecureRandom`.
 *  - Ele é armazenado no **label** do `ClipDescription` (campo público,
 *    sem relação com a senha) e no `Data` do WorkManager.
 *  - O worker compara o nonce do label com o nonce do `Data`.
 *  - **Nunca** derivamos nada da senha (nem `hashCode`, nem hash).
 *    Isso elimina a possibilidade de reverter o valor persistido por
 *    força bruta, mesmo que o banco do WorkManager seja lido.
 *
 * Limpeza incondicional:
 *  - Se o app estiver em segundo plano (API 29+), `primaryClip` retorna
 *    `null`; o worker **limpa mesmo assim**, sem tentar ler.
 *  - Se o clip atual não for o nosso (nonce diferente), também limpamos
 *    por segurança — o pior caso é apagar um clip alheio, o que é
 *    preferível a deixar uma senha exposta.
 */
object ClipboardUtil {

    /**
     * Copia [value] para o clipboard, marca como sensível e agenda a
     * limpeza em 30 s.
     */
    fun copySensitive(context: Context, label: String, value: String) {
        val cm = context.getSystemService<ClipboardManager>() ?: return

        // Nonce aleatório — 128 bits, sem relação com a senha.
        val nonce = generateNonce()

        // Label do clip inclui o nonce. O label é visível para o usuário
        // (aparece em algumas UIs de clipboard), então usamos um prefixo
        // legível + o nonce.
        val clipLabel = "KeySecure:$nonce"
        val clip = ClipData.newPlainText(clipLabel, value)

        val extras = PersistableBundle().apply {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
            } else {
                putBoolean(KEY_IS_SENSITIVE_LEGACY, true)
            }
        }
        clip.description.extras = extras
        cm.setPrimaryClip(clip)

        scheduleClear(context, nonce, clipLabel)
    }

    private fun scheduleClear(context: Context, nonce: String, clipLabel: String) {
        val request = OneTimeWorkRequestBuilder<ClipboardClearWorker>()
            .setInitialDelay(CLEAR_DELAY_SECONDS, TimeUnit.SECONDS)
            .setInputData(
                Data.Builder()
                    .putString(KEY_NONCE, nonce)
                    .putString("clip_label", clipLabel)
                    .build()
            )
            .build()

        WorkManager.getInstance(context).enqueueUniqueWork(
            WORK_NAME,
            ExistingWorkPolicy.REPLACE,
            request
        )
    }

    fun clearNow(context: Context) {
        WorkManager.getInstance(context).cancelUniqueWork(WORK_NAME)
        val cm = context.getSystemService<ClipboardManager>() ?: return
        clearClip(cm)
    }

    private fun clearClip(cm: ClipboardManager) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                cm.clearPrimaryClip()
            } else {
                @Suppress("DEPRECATION")
                cm.setPrimaryClip(ClipData.newPlainText("", ""))
            }
        } catch (_: Throwable) { /* best-effort */ }
    }

    private fun generateNonce(): String {
        val bytes = ByteArray(16)
        nonceRandom.nextBytes(bytes)
        return bytes.joinToString("") { "%02x".format(it) }
    }
}

/**
 * Worker que executa após 30 s.
 *
 * Estratégia de limpeza:
 *  1. Lê o clip atual.
 *  2. Se `primaryClip == null` (app em background, API 29+) → **limpa
 *     incondicionalmente**. Não podemos verificar o nonce, então
 *     assumimos o pior caso.
 *  3. Se o clip atual tem o nonce esperado → limpa.
 *  4. Se o clip atual tem outro nonce → **também limpa** por segurança.
 *     O usuário pode ter copiado outra coisa, mas é preferível apagar
 *     um clip alheio a deixar uma senha exposta.
 */
class ClipboardClearWorker(
    context: Context,
    params: WorkerParameters
) : Worker(context, params) {

    override fun doWork(): Result {
        val cm = applicationContext.getSystemService<ClipboardManager>()
            ?: return Result.success()

        val expectedNonce = inputData.getString(KEY_NONCE)
        val expectedLabel = inputData.getString("clip_label")

        val current = runCatching { cm.primaryClip }.getOrNull()

        when {
            // Não conseguimos ler o clip → limpa incondicionalmente.
            current == null -> clearClip(cm)

            // Temos o clip, mas o label é diferente do esperado
            //    (outro app sobrescreveu, ou é o nosso nonce antigo).
            //    Limpa mesmo assim por segurança.
            expectedLabel != null && current.description.label != expectedLabel ->
                clearClip(cm)

            // Nonce bate (ou não conseguimos comparar o label):
            //    limpa.
            else -> clearClip(cm)
        }

        return Result.success()
    }

    private fun clearClip(cm: ClipboardManager) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                cm.clearPrimaryClip()
            } else {
                @Suppress("DEPRECATION")
                cm.setPrimaryClip(ClipData.newPlainText("", ""))
            }
        } catch (_: Throwable) { /* best-effort */ }
    }
}
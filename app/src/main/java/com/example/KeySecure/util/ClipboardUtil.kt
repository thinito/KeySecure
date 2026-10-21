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
import java.util.concurrent.TimeUnit

// ---------------------------------------------------------------------------
// Constantes compartilhadas entre ClipboardUtil e ClipboardClearWorker.
// Ficam no nível do arquivo (não dentro do object) para que o worker — que
// é uma classe separada — também possa enxergá-las.
// `private` no top-level significa "privado a este arquivo", o que é
// exatamente o escopo desejado.
// ---------------------------------------------------------------------------
private const val CLEAR_DELAY_SECONDS = 30L
private const val WORK_NAME = "clipboard_clear"
private const val KEY_VALUE_HASH = "value_hash"

/**
 * String idêntica a `ClipDescription.EXTRA_IS_SENSITIVE` (API 33+),
 * usada como best-effort em APIs 24–32. Muitos teclados/autofill
 * honram essa chave mesmo antes da constante existir.
 */
private const val EXTRA_IS_SENSITIVE_LEGACY = "android.content.extra.IS_SENSITIVE"

/**
 * Copia senhas para o clipboard e agenda limpeza em 30 s via WorkManager.
 *
 * Por que WorkManager e não Handler:
 *   - O Handler morre junto com o processo. Se o usuário sai do app,
 *     a senha fica no clipboard indefinidamente.
 *   - WorkManager sobrevive à morte do processo, reboot e Doze (com
 *     atraso em Doze — trade-off de bateria × precisão).
 *
 * Limitações conhecidas do Android 10+:
 *   - Em segundo plano, `primaryClip` retorna null para apps comuns.
 *     Por isso o worker **limpa mesmo sem conseguir ler**. É melhor
 *     destruir um clip alheio do que deixar uma senha exposta.
 *   - `clearPrimaryClip()` pode ser um no-op se o app estiver em
 *     background em OEMs agressivos. Best-effort.
 */
object ClipboardUtil {

    /**
     * Copia [value] para o clipboard marcando como sensível e agenda a
     * limpeza em 30 s. Chamadas repetidas substituem o agendamento anterior.
     */
    fun copySensitive(context: Context, label: String, value: String) {
        val cm = context.getSystemService<ClipboardManager>() ?: return
        val clip = ClipData.newPlainText(label, value)

        val extras = PersistableBundle().apply {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
            } else {
                // Mesmo valor da constante; honrado como best-effort em API 24-32.
                putBoolean(EXTRA_IS_SENSITIVE_LEGACY, true)
            }
        }
        clip.description.extras = extras
        cm.setPrimaryClip(clip)

        scheduleClear(context, value)
    }

    /**
     * Agenda a limpeza. Só passa o `hashCode()` do valor (32 bits, não
     * reversível) para o WorkManager — nunca a senha em claro.
     */
    private fun scheduleClear(context: Context, value: String) {
        val request = OneTimeWorkRequestBuilder<ClipboardClearWorker>()
            .setInitialDelay(CLEAR_DELAY_SECONDS, TimeUnit.SECONDS)
            .setInputData(
                Data.Builder().putInt(KEY_VALUE_HASH, value.hashCode()).build()
            )
            .build()

        WorkManager.getInstance(context).enqueueUniqueWork(
            WORK_NAME,
            ExistingWorkPolicy.REPLACE,
            request
        )
    }

    /**
     * Limpa imediatamente e cancela qualquer agendamento pendente.
     * Útil quando o usuário tranca o cofre manualmente.
     */
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
        } catch (t: Throwable) {
            // Best-effort: em background OEMs podem recusar. Log e segue.
        }
    }
}

/**
 * Worker que executa após 30 s. Precisa ser top-level (WorkManager
 * instancia por reflexão) e público.
 */
class ClipboardClearWorker(
    context: Context,
    params: WorkerParameters
) : Worker(context, params) {

    override fun doWork(): Result {
        val cm = applicationContext.getSystemService<ClipboardManager>()
            ?: return Result.success()

        val expectedHash = inputData.getInt(KEY_VALUE_HASH, Int.MIN_VALUE)
        val current = cm.primaryClip

        val shouldClear: Boolean = if (current != null && current.itemCount > 0) {
            // Podemos ler: só limpa se ainda for o valor que colocamos.
            val text = current.getItemAt(0).text?.toString() ?: ""
            expectedHash == Int.MIN_VALUE || text.hashCode() == expectedHash
        } else {
            // Não conseguimos ler (background em API 29+, ou clip já vazio).
            // Limpa mesmo assim: preferimos destruir um clip alheio a deixar
            // uma senha exposta.
            true
        }

        if (shouldClear) {
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    cm.clearPrimaryClip()
                } else {
                    @Suppress("DEPRECATION")
                    cm.setPrimaryClip(ClipData.newPlainText("", ""))
                }
            } catch (t: Throwable) {
                // OEM pode recusar clear em background. Best-effort.
            }
        }
        return Result.success()
    }
}
package com.example.KeySecure.util

import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.content.FileProvider
import java.io.File
import java.io.FileOutputStream
import java.io.PrintWriter
import java.io.StringWriter
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/**
 * Logger persistente de erros.
 *
 * - Escreve em `getExternalFilesDir(null)/logs/` — acessível via USB/ADB
 *   sem permissão especial.
 * - Instala `UncaughtExceptionHandler` para capturar crashes.
 * - Rotaciona arquivos por data (`app-YYYY-MM-DD.log`) e por tamanho
 *   (máx. 1 MB por arquivo, máx. 7 arquivos).
 * - Usa `fsync` em cada escrita — garante que os dados cheguem ao disco
 *   mesmo quando o processo morre logo em seguida (crash handler).
 *
 * NUNCA armazene segredos nos logs. Senhas, PINs e frases-chave **não**
 * devem aparecer aqui.
 */
object CrashLogger {

    private const val MAX_FILE_SIZE_BYTES = 1_000_000L   // 1 MB por arquivo
    private const val MAX_FILES = 7                       // 7 arquivos (~7 dias)
    private const val LOG_DIR_NAME = "logs"

    private val lock = Any()
    private val dateFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US)
    private val dayFormat = SimpleDateFormat("yyyy-MM-dd", Locale.US)

    @Volatile private var logDir: File? = null
    @Volatile private var currentFile: File? = null
    @Volatile private var currentDay: String = ""

    /**
     * Instala o handler. Chamar em `Application.onCreate()`.
     * Idempotente — chamadas repetidas são no-op.
     */
    fun install(context: Context) {
        synchronized(lock) {
            if (logDir != null) return

            val base = context.getExternalFilesDir(null) ?: context.filesDir
            logDir = File(base, LOG_DIR_NAME).apply { mkdirs() }
            rotateOldFiles()
        }

        val previous = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            try {
                writeLog(
                    level = "FATAL",
                    tag = "Crash",
                    message = "Uncaught exception in thread ${thread.name}",
                    throwable = throwable
                )
            } catch (_: Throwable) {
                // Nunca deixe o handler de crash causar outro crash
            } finally {
                previous?.uncaughtException(thread, throwable)
            }
        }

        logDeviceInfo(context)
    }

    // ------------------------------------------------------------------
    // API de escrita
    // ------------------------------------------------------------------
    fun d(tag: String, message: String, throwable: Throwable? = null) =
        writeLog("DEBUG", tag, message, throwable)

    fun i(tag: String, message: String, throwable: Throwable? = null) =
        writeLog("INFO", tag, message, throwable)

    fun w(tag: String, message: String, throwable: Throwable? = null) =
        writeLog("WARN", tag, message, throwable)

    fun e(tag: String, message: String, throwable: Throwable? = null) =
        writeLog("ERROR", tag, message, throwable)

    fun f(tag: String, message: String, throwable: Throwable? = null) =
        writeLog("FATAL", tag, message, throwable)

    private fun writeLog(level: String, tag: String, message: String, throwable: Throwable?) {
        synchronized(lock) {
            try {
                val dir = logDir ?: return
                val now = Date()
                val day = dayFormat.format(now)

                // Garante arquivo do dia
                if (day != currentDay || currentFile == null || currentFile?.exists() != true) {
                    currentDay = day
                    currentFile = File(dir, "app-$day.log")
                }
                val file = currentFile ?: return

                val sb = StringBuilder()
                sb.append('[').append(dateFormat.format(now)).append("] ")
                sb.append('[').append(level).append("] ")
                sb.append('[').append(Thread.currentThread().name).append("] ")
                sb.append('[').append(tag).append("] ")
                sb.append(message).append('\n')

                throwable?.let {
                    val sw = StringWriter()
                    it.printStackTrace(PrintWriter(sw))
                    sb.append(sw.toString()).append('\n')
                }

                val bytes = sb.toString().toByteArray(Charsets.UTF_8)
                FileOutputStream(file, true).use { fos ->
                    fos.write(bytes)
                    fos.flush()
                    // ✅ fsync — sobrevive a crash iminente
                    fos.fd.sync()
                }

                // Rotaciona se excedeu o tamanho
                if (file.length() > MAX_FILE_SIZE_BYTES) {
                    val rotated = File(dir, "app-$day-${System.currentTimeMillis()}.log")
                    file.renameTo(rotated)
                    currentFile = File(dir, "app-$day.log")
                }

                // Remove arquivos antigos
                rotateOldFiles()
            } catch (_: Throwable) {
                // Falha silenciosa — não podemos logar erros de log
            }
        }
    }

    private fun rotateOldFiles() {
        val dir = logDir ?: return
        val files = dir.listFiles { f -> f.extension == "log" } ?: return
        if (files.size <= MAX_FILES) return
        files.sortedBy { it.lastModified() }
            .take(files.size - MAX_FILES)
            .forEach { runCatching { it.delete() } }
    }

    // ------------------------------------------------------------------
    // Info do dispositivo (útil para diagnóstico)
    // ------------------------------------------------------------------
    private fun logDeviceInfo(context: Context) {
        try {
            val info = buildString {
                appendLine("=== KeySecure iniciado ===")
                appendLine("App: ${context.packageName}")
                appendLine("Android: ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})")
                appendLine("Device: ${Build.MANUFACTURER} ${Build.MODEL}")
                appendLine("Locale: ${Locale.getDefault()}")
                appendLine("TimeZone: ${TimeZone.getDefault().id}")
                appendLine("Timestamp: ${Date()}")
                appendLine("=========================")
            }
            writeLog("INFO", "DeviceInfo", info, null)
        } catch (_: Throwable) { /* ignora */ }
    }

    // ------------------------------------------------------------------
    // Acesso externo
    // ------------------------------------------------------------------
    fun getLogDir(): File? = logDir

    /** Caminho absoluto do diretório de logs, para exibir ao usuário. */
    fun getLogPath(): String? = logDir?.absolutePath

    /**
     * Retorna o conteúdo dos logs mais recentes (até [maxBytes]).
     * Prefere arquivos mais recentes.
     */
    fun getRecentLogs(maxBytes: Long = 2_000_000L): String {
        val dir = logDir ?: return "Nenhum log disponível."
        val files = dir.listFiles { f -> f.extension == "log" }
            ?.sortedByDescending { it.lastModified() }
            ?: return "Nenhum log disponível."

        val sb = StringBuilder()
        var total = 0L
        for (f in files) {
            if (total >= maxBytes) break
            sb.append("\n===== ${f.name} =====\n")
            val content = runCatching { f.readText() }.getOrDefault("")
            val remaining = (maxBytes - total).toInt().coerceAtLeast(0)
            if (content.length > remaining) {
                sb.append(content.takeLast(remaining))
                total = maxBytes
            } else {
                sb.append(content)
                total += content.length
            }
        }
        return sb.toString()
    }

    /**
     * Abre o share sheet do Android com os logs concatenados.
     * O usuário pode salvar em Downloads, Drive, e-mail, etc.
     */
    fun shareLogs(context: Context) {
        try {
            val logs = getRecentLogs()
            if (logs.isBlank()) {
                android.widget.Toast.makeText(
                    context,
                    "Nenhum log disponível",
                    android.widget.Toast.LENGTH_SHORT
                ).show()
                return
            }
            val temp = File(context.cacheDir, "keysecure-logs.txt")
            temp.writeText(logs)
            val uri = FileProvider.getUriForFile(
                context,
                "${context.packageName}.fileprovider",
                temp
            )
            val intent = Intent(Intent.ACTION_SEND).apply {
                type = "text/plain"
                putExtra(Intent.EXTRA_STREAM, uri)
                putExtra(Intent.EXTRA_SUBJECT, "KeySecure — logs")
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            context.startActivity(Intent.createChooser(intent, "Compartilhar logs"))
        } catch (t: Throwable) {
            android.widget.Toast.makeText(
                context,
                "Falha ao compartilhar: ${t.message}",
                android.widget.Toast.LENGTH_LONG
            ).show()
        }
    }

    /** Remove todos os logs. */
    fun clearAll() {
        synchronized(lock) {
            runCatching {
                logDir?.listFiles()?.forEach { it.delete() }
                currentFile = null
                currentDay = ""
            }
        }
    }
}
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.core.content.getSystemService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

object ClipboardUtil {

    private var clearJob: Job? = null
    private const val CLEAR_DELAY_MS = 30_000L

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
            // Só limpa se ainda formos os donos do clip
            val current = cm.primaryClip
            if (current != null &&
                current.getItemAt(0).text?.toString() == value) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    cm.clearPrimaryClip()
                } else {
                    cm.setPrimaryClip(ClipData.newPlainText("", ""))
                }
            }
        }
    }
}
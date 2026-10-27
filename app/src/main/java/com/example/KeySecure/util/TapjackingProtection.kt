package com.example.KeySecure.util

import android.os.Build
import android.view.MotionEvent
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.pointer.pointerInteropFilter

/**
 * Rejeita toques quando a janela está total ou parcialmente obscurecida
 * por outra janela (tapjacking).
 *
 * Defesa em profundidade:
 *  - A proteção principal é `window.decorView.filterTouchesWhenObscured = true`
 *    no `MainActivity.onCreate()`, que cancela os eventos **antes** de chegarem
 *    ao Compose.
 *  - Este Modifier atua no pipeline do Compose. É útil se a proteção global
 *    for removida, ou se algum composable específico for renderizado em
 *    contexto onde a proteção global não se aplica.
 *
 * `pointerInteropFilter` é `@ExperimentalComposeUiApi` porque expõe o
 * `MotionEvent` cru para inspeção das flags. Optamos explicitamente por
 * essa API — é estável na prática e não tem substituto direto no pipeline
 * atual do Compose.
 */
@OptIn(ExperimentalComposeUiApi::class)
fun Modifier.filterObscuredTouches(
    onObscured: () -> Unit = {}
): Modifier = this.pointerInteropFilter { event ->
    if (isObscured(event)) {
        onObscured()
        true   // consome o toque — não chega ao componente
    } else {
        false  // deixa o Compose processar normalmente
    }
}

/**
 * Verifica se o [MotionEvent] carrega a flag de janela obscurecida.
 *
 * Em API 31+:
 *  - `FLAG_WINDOW_IS_PARTIALLY_OBSCURED`: sobreposição parcial (widget flutuante,
 *    bolha, etc.) — suspeita em gerenciador de senhas.
 *  - `FLAG_WINDOW_IS_OBSCURED` (deprecated mas ainda emitido): totalmente obscurecida.
 *
 * Em API < 31: apenas `FLAG_WINDOW_IS_OBSCURED`.
 */
fun isObscured(event: MotionEvent): Boolean {
    val flags = event.flags
    return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        (flags and MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED) != 0 ||
                @Suppress("DEPRECATION")
                (flags and MotionEvent.FLAG_WINDOW_IS_OBSCURED) != 0
    } else {
        @Suppress("DEPRECATION")
        (flags and MotionEvent.FLAG_WINDOW_IS_OBSCURED) != 0
    }
}
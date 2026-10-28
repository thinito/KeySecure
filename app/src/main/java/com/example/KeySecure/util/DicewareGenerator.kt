package com.example.KeySecure.util

import android.content.Context
import java.security.SecureRandom

/**
 * Gerador de frases Diceware.
 *
 * Usa a lista EFF Short Wordlist (2ª edição, 1296 palavras curtas)
 * embarcada em `assets/eff_short_wordlist_2_0.txt`. 6 palavras dessa
 * lista fornecem ≈ 62 bits de entropia (1296^6 ≈ 2^62).
 *
 * A lista é lida uma vez e mantida em memória.
 */
object DicewareGenerator {

    private const val ASSET_NAME = "eff_short_wordlist_2_0.txt"
    private const val DEFAULT_WORD_COUNT = 6

    private val random = SecureRandom()

    @Volatile
    private var wordlist: List<String>? = null

    /**
     * Gera uma frase Diceware com [wordCount] palavras.
     * @throws IllegalStateException se a lista não estiver disponível.
     */
    fun generate(context: Context, wordCount: Int = DEFAULT_WORD_COUNT): String {
        require(wordCount >= 4) { "Diceware exige pelo menos 4 palavras" }
        val words = loadWordlist(context)
        return (1..wordCount)
            .map { words[random.nextInt(words.size)] }
            .joinToString(" ")
    }

    private fun loadWordlist(context: Context): List<String> {
        wordlist?.let { return it }
        synchronized(this) {
            wordlist?.let { return it }
            val loaded = try {
                context.assets.open(ASSET_NAME)
                    .bufferedReader()
                    .useLines { lines ->
                        lines.map { it.trim() }
                            .filter { it.isNotEmpty() && !it.startsWith("#") }
                            .toList()
                    }
            } catch (t: Throwable) {
                throw IllegalStateException(
                    "Lista Diceware não encontrada em assets/$ASSET_NAME",
                    t
                )
            }
            require(loaded.size >= 1000) {
                "Lista Diceware muito pequena: ${loaded.size} palavras"
            }
            wordlist = loaded
            return loaded
        }
    }
}
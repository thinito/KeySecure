package com.example.KeySecure

import com.example.KeySecure.crypto.Crypto
import com.example.KeySecure.data.SecurityPolicy
import com.example.KeySecure.data.VaultEnvelope
import com.example.KeySecure.util.base64
import com.example.KeySecure.util.toBase64
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.*
import kotlinx.serialization.decodeFromString
import java.io.File
import javax.crypto.SecretKey

/**
 * Cofre local. Persiste em vault.json com envelope versionado.
 */
class Vault(private val vaultFile: File) {

    private var keyBytes: ByteArray? = null

    @Volatile
    var unlocked: Boolean = false
        private set

    private val json = Json { ignoreUnknownKeys = true; prettyPrint = false }

    // ------------------------------------------------------------------
    // Criação
    // ------------------------------------------------------------------
    fun create(pin: CharArray, passphrase: CharArray) {
        require(SecurityPolicy.isValidPin(String(pin))) { "PIN inválido" }
        require(SecurityPolicy.isValidPassphrase(String(passphrase))) {
            "Frase-chave muito curta"
        }

        // 1) Chave mestra aleatória do cofre (32 bytes)
        val master = Crypto.randomBytes(32)

        // 2) Salts independentes
        val saltPin = Crypto.randomBytes(SecurityPolicy.SALT_LENGTH_BYTES)
        val saltPhrase = Crypto.randomBytes(SecurityPolicy.SALT_LENGTH_BYTES)

        // 3) Deriva chaves de embrulho
        val kPin = Crypto.derive(pin, saltPin)
        val kPhrase = Crypto.derive(passphrase, saltPhrase)

        // 4) Embrulha a master key com cada uma
        val wrappedPin = Crypto.encrypt(kPin, master)
        val wrappedPhrase = Crypto.encrypt(kPhrase, master)

        // 5) Envelope
        val envelope = VaultEnvelope(
            version = 2,
            kdfIterations = SecurityPolicy.PBKDF2_ITERATIONS,
            saltPin = saltPin.toBase64(),
            saltPhrase = saltPhrase.toBase64(),
            wrappedKeyPin = wrappedPin.toBase64(),
            wrappedKeyPhrase = wrappedPhrase.toBase64(),
            entries = emptyList()
        )
        persist(envelope)

        // 6) Mantém a master key em memória
        setKey(master)

        // 7) Limpa buffers sensíveis
        pin.fill('\u0000')
        passphrase.fill('\u0000')
        kPin.encoded.fill(0)
        kPhrase.encoded.fill(0)
    }

    // ------------------------------------------------------------------
    // Desbloqueio
    // ------------------------------------------------------------------
    fun unlockPin(pin: CharArray): Boolean = try {
        val env = readEnvelope() ?: return false
        val salt = env.saltPin.base64()
        val kPin = Crypto.derive(pin, salt, env.kdfIterations)
        val master = Crypto.decrypt(kPin, env.wrappedKeyPin.base64())

        setKey(master)
        migrateIfNeeded(pin, master, env)
        true
    } catch (t: Throwable) {
        false
    } finally {
        pin.fill('\u0000')
    }

    fun unlockPhrase(phrase: CharArray): Boolean = try {
        val env = readEnvelope() ?: return false
        val salt = env.saltPhrase.base64()
        val kPh = Crypto.derive(phrase, salt, env.kdfIterations)
        val master = Crypto.decrypt(kPh, env.wrappedKeyPhrase.base64())

        setKey(master)
        true
    } catch (t: Throwable) {
        false
    } finally {
        phrase.fill('\u0000')
    }

    // ------------------------------------------------------------------
    // Migração v1 -> v2 (aumento de iterações)
    // ------------------------------------------------------------------
    private fun migrateIfNeeded(pin: CharArray, master: ByteArray, env: VaultEnvelope) {
        if (env.kdfIterations >= SecurityPolicy.PBKDF2_ITERATIONS) return
        val newSalt = Crypto.randomBytes(SecurityPolicy.SALT_LENGTH_BYTES)
        val kPin = Crypto.derive(pin, newSalt) // já usa o novo padrão
        val rewrapped = Crypto.encrypt(kPin, master)
        persist(
            env.copy(
                kdfIterations = SecurityPolicy.PBKDF2_ITERATIONS,
                saltPin = newSalt.toBase64(),
                wrappedKeyPin = rewrapped.toBase64()
            )
        )
        kPin.encoded.fill(0)
    }

    // ------------------------------------------------------------------
    // Key lifecycle
    // ------------------------------------------------------------------
    private fun setKey(bytes: ByteArray) {
        keyBytes?.fill(0)
        keyBytes = bytes.copyOf()
        unlocked = true
    }

    fun key(): SecretKey {
        val b = keyBytes ?: error("Cofre trancado")
        return javax.crypto.spec.SecretKeySpec(b, "AES")
    }

    fun lock() {
        keyBytes?.fill(0)
        keyBytes = null
        unlocked = false
    }

    // ------------------------------------------------------------------
    // Persistência
    // ------------------------------------------------------------------
    private fun persist(env: VaultEnvelope) {
        vaultFile.writeText(json.encodeToString(VaultEnvelope.serializer(), env))
    }

    private fun readEnvelope(): VaultEnvelope? =
        if (!vaultFile.exists()) null
        else runCatching {
            json.decodeFromString(VaultEnvelope.serializer(), vaultFile.readText())
        }.getOrNull()
}
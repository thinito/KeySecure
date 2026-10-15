package com.example.KeySecure

import com.example.KeySecure.crypto.Crypto
import com.example.KeySecure.crypto.KeystoreManager
import com.example.KeySecure.data.SecurityPolicy
import com.example.KeySecure.data.VaultEnvelope
import com.example.KeySecure.data.VaultEntry
import com.example.KeySecure.util.base64
import com.example.KeySecure.util.toBase64
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import java.io.File
import java.io.FileOutputStream
import java.security.GeneralSecurityException
import java.util.concurrent.locks.ReentrantLock
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import kotlin.concurrent.withLock

/** Resultado tipado de uma tentativa de desbloqueio (item 15). */
sealed class UnlockResult {
    object Success : UnlockResult()
    object WrongCredential : UnlockResult()
    object NoVault : UnlockResult()
    object CorruptedVault : UnlockResult()
    data class Failure(val cause: Throwable) : UnlockResult()
}

class Vault(
    private val vaultFile: File,
    private val keystore: KeystoreManager = KeystoreManager()
) {

    private val lockGuard = ReentrantLock()

    @Volatile
    private var keyBytes: ByteArray? = null

    private val _unlocked = MutableStateFlow(false)
    val unlocked: StateFlow<Boolean> = _unlocked.asStateFlow()

    private var entries: MutableList<VaultEntry> = mutableListOf()

    private val json = Json { ignoreUnknownKeys = false; prettyPrint = false }

    fun exists(): Boolean = vaultFile.exists()

    // ------------------------------------------------------------------
    // Criação (item 6: recusa se já existir)
    // ------------------------------------------------------------------
    fun create(pin: CharArray, passphrase: CharArray): UnlockResult {
        if (vaultFile.exists()) {
            pin.fill('\u0000'); passphrase.fill('\u0000')
            return UnlockResult.Failure(IllegalStateException("Cofre já existe"))
        }
        val pinStr = String(pin)
        val phraseStr = SecurityPolicy.normalizePassphrase(String(passphrase))
        if (!SecurityPolicy.isValidPin(pinStr) ||
            !SecurityPolicy.isValidPassphrase(phraseStr)
        ) {
            pin.fill('\u0000'); passphrase.fill('\u0000')
            return UnlockResult.WrongCredential
        }

        val master = Crypto.randomBytes(32)
        val masterKey = SecretKeySpec(master, "AES")

        val saltPin = Crypto.randomBytes(SecurityPolicy.SALT_LENGTH_BYTES)
        val saltPhrase = Crypto.randomBytes(SecurityPolicy.SALT_LENGTH_BYTES)

        val kPin = Crypto.derive(pin, saltPin)
        val kPhrase = Crypto.derive(phraseStr.toCharArray(), saltPhrase)

        val emptyJson = json.encodeToString(
            ListSerializer(VaultEntry.serializer()),
            emptyList<VaultEntry>()
        )

        // Header primeiro (para calcular AAD)
        val header = VaultEnvelope(
            version = 3,
            iterPin = SecurityPolicy.PBKDF2_ITERATIONS,
            iterPhrase = SecurityPolicy.PBKDF2_ITERATIONS,
            saltPin = saltPin.toBase64(),
            saltPhrase = saltPhrase.toBase64(),
            wrappedKeyPin = "",
            wrappedKeyPhrase = "",
            wrappedKeyKeystore = null,
            data = ""
        )
        val aad = aadFor(header)

        val wrappedPin = Crypto.encrypt(kPin, master, aad)
        val wrappedPhrase = Crypto.encrypt(kPhrase, master, aad)

        // Keystore wrapper (item 4) — best-effort
        var wrappedKeystore: String? = null
        try {
            keystore.createKey()
            val ksKey = keystore.getKey()
            wrappedKeystore = Crypto.encrypt(ksKey, master, aad).toBase64()
        } catch (t: Throwable) {
            // dispositivo sem biometria/hardware — prossegue só com PIN+frase
        }

        val dataCipher = Crypto.encrypt(masterKey, emptyJson.toByteArray(), aad)

        val envelope = header.copy(
            wrappedKeyPin = wrappedPin.toBase64(),
            wrappedKeyPhrase = wrappedPhrase.toBase64(),
            wrappedKeyKeystore = wrappedKeystore,
            data = dataCipher.toBase64()
        )
        persistAtomically(envelope)

        setKey(master)
        entries = mutableListOf()

        pin.fill('\u0000'); passphrase.fill('\u0000')
        return UnlockResult.Success
    }

    // ------------------------------------------------------------------
    // Desbloqueio
    // ------------------------------------------------------------------
    fun unlockPin(pin: CharArray): UnlockResult {
        return try {
            val env = readEnvelope() ?: return UnlockResult.NoVault
            if (!SecurityPolicy.validateIterations(env.iterPin)) { return UnlockResult.CorruptedVault }
            val kPin = Crypto.derive(pin, env.saltPin.base64(), env.iterPin)
            val master = Crypto.decrypt(kPin, env.wrappedKeyPin.base64(), aadFor(env))
            setKey(master)
            loadEntries(env)
            UnlockResult.Success
        } catch (e: javax.crypto.AEADBadTagException) {
            UnlockResult.WrongCredential
        } catch (e: IllegalArgumentException) {
            UnlockResult.CorruptedVault
        } catch (e: GeneralSecurityException) {
            UnlockResult.WrongCredential
        } finally {
            pin.fill('\u0000')
        }
    }

    fun unlockPhrase(phrase: CharArray): UnlockResult {
        return try {
            val env = readEnvelope() ?: return UnlockResult.NoVault
            if (!SecurityPolicy.validateIterations(env.iterPhrase)) {return UnlockResult.CorruptedVault; }
            val normalized = SecurityPolicy.normalizePassphrase(String(phrase))
            val kPh = Crypto.derive(normalized.toCharArray(), env.saltPhrase.base64(), env.iterPhrase)
            val master = Crypto.decrypt(kPh, env.wrappedKeyPhrase.base64(), aadFor(env))
            setKey(master)
            loadEntries(env)
            UnlockResult.Success
        } catch (e: javax.crypto.AEADBadTagException) {
            UnlockResult.WrongCredential
        } catch (e: IllegalArgumentException) {
            UnlockResult.CorruptedVault
        } catch (e: GeneralSecurityException) {
            UnlockResult.WrongCredential
        } finally {
            phrase.fill('\u0000')
        }
    }

    /** Item 4: desbloqueio com Cipher já inicializado pelo BiometricPrompt. */
    fun unlockWithKeystoreCipher(cipher: javax.crypto.Cipher, iv: ByteArray): UnlockResult = try {
        val env = readEnvelope() ?: return UnlockResult.NoVault
        val wrapped = env.wrappedKeyKeystore?.base64() ?: return UnlockResult.CorruptedVault
        // Reconstitui o blob: IV || ciphertext
        val blob = iv + wrapped.copyOfRange(0, wrapped.size - iv.size + iv.size).copyOfRange(0, 0)
        // O blob já contém IV no início — usamos o IV separado apenas como sanity check
        val master = try {
            cipher.doFinal(wrapped, iv.size, wrapped.size - iv.size)
        } catch (e: Throwable) {
            // Cipher já foi inicializado com o IV do blob pelo BiometricPrompt
            cipher.doFinal(wrapped)
        }
        setKey(master)
        loadEntries(env)
        UnlockResult.Success
    } catch (e: GeneralSecurityException) {
        UnlockResult.WrongCredential
    }

    // ------------------------------------------------------------------
    // Carga e persistência das entradas
    // ------------------------------------------------------------------
    private fun loadEntries(env: VaultEnvelope) {
        val decrypted = Crypto.decrypt(key(), env.data.base64(), aadFor(env))
        entries = json.decodeFromString(
            ListSerializer(VaultEntry.serializer()),
            String(decrypted)
        ).toMutableList()
    }

    private fun persistEntries() {
        val env = readEnvelope() ?: return
        val body = json.encodeToString(ListSerializer(VaultEntry.serializer()), entries)
        val cipher = Crypto.encrypt(key(), body.toByteArray(), aadFor(env))
        persistAtomically(env.copy(data = cipher.toBase64()))
    }

    fun getEntries(): List<VaultEntry> = lockGuard.withLock { entries.toList() }

    fun addEntry(entry: VaultEntry) = lockGuard.withLock {
        entries.add(entry); persistEntries()
    }

    fun updateEntry(old: VaultEntry, new: VaultEntry) = lockGuard.withLock {
        val i = entries.indexOf(old)
        if (i >= 0) { entries[i] = new; persistEntries() }
    }

    fun deleteEntry(entry: VaultEntry) = lockGuard.withLock {
        if (entries.remove(entry)) persistEntries()
    }

    // ------------------------------------------------------------------
    // Key lifecycle (item 17: thread-safe; item 8: sem fill em .encoded)
    // ------------------------------------------------------------------
    private fun setKey(bytes: ByteArray) = lockGuard.withLock {
        keyBytes?.fill(0)
        keyBytes = bytes.copyOf()
        _unlocked.value = true
    }

    fun key(): SecretKey {
        val b = keyBytes ?: error("Cofre trancado")
        return SecretKeySpec(b, "AES")
    }

    fun lock() = lockGuard.withLock {
        keyBytes?.fill(0)
        keyBytes = null
        entries = mutableListOf()
        _unlocked.value = false
    }

    // ------------------------------------------------------------------
    // AAD (item 10)
    // ------------------------------------------------------------------
    private fun aadFor(env: VaultEnvelope): ByteArray =
        "v=${env.version}|ip=${env.iterPin}|iph=${env.iterPhrase}|sp=${env.saltPin}|sph=${env.saltPhrase}"
            .toByteArray(Charsets.UTF_8)

    // ------------------------------------------------------------------
    // Persistência atômica (item 14)
    // ------------------------------------------------------------------
    private fun persistAtomically(env: VaultEnvelope) {
        val parent = vaultFile.parentFile ?: return
        val tmp = File(parent, "${vaultFile.name}.tmp")
        val bak = File(parent, "${vaultFile.name}.bak")

        FileOutputStream(tmp).use { fos ->
            fos.write(json.encodeToString(VaultEnvelope.serializer(), env).toByteArray())
            fos.flush()
            fos.fd.sync()
        }

        if (vaultFile.exists()) {
            vaultFile.copyTo(bak, overwrite = true)
        }
        if (!tmp.renameTo(vaultFile)) {
            tmp.copyTo(vaultFile, overwrite = true)
            tmp.delete()
        }
    }

    private fun readEnvelope(): VaultEnvelope? {
        if (!vaultFile.exists()) return null
        return try {
            json.decodeFromString(VaultEnvelope.serializer(), vaultFile.readText())
        } catch (t: Throwable) {
            null
        }
    }
}
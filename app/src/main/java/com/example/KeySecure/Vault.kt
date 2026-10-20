package com.example.KeySecure

import com.example.KeySecure.crypto.Crypto
import com.example.KeySecure.crypto.IKeystore
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
import java.io.IOException
import java.security.GeneralSecurityException
import java.util.UUID
import java.util.concurrent.locks.ReentrantLock
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import kotlin.concurrent.withLock

sealed class UnlockResult {
    object Success : UnlockResult()
    object WrongCredential : UnlockResult()
    object NoVault : UnlockResult()
    object CorruptedVault : UnlockResult()

    /** Vault v4 requer pepper, mas a chave HMAC do Keystore não existe mais. */
    object NoPepper : UnlockResult()

    /** Vault criado numa versão anterior à do pepper — só frase abre. */
    object LegacyVaultNoPepper : UnlockResult()

    data class Failure(val cause: Throwable) : UnlockResult()
}

class Vault(
    private val vaultFile: File,
    private val keystore: IKeystore = KeystoreManager()
) {

    private val lockGuard = ReentrantLock()

    @Volatile
    private var keyBytes: ByteArray? = null

    private val _unlocked = MutableStateFlow(false)
    val unlocked: StateFlow<Boolean> = _unlocked.asStateFlow()

    private val _exists = MutableStateFlow(vaultFile.exists())
    val exists: StateFlow<Boolean> = _exists.asStateFlow()

    private var entries: MutableList<VaultEntry> = mutableListOf()

    private val json = Json {
        ignoreUnknownKeys = false
        prettyPrint = false
    }

    fun fileExists(): Boolean = vaultFile.exists()
    fun keystoreManager(): IKeystore = keystore

    // ------------------------------------------------------------------
    // Derivação endurecida por hardware (PIN)
    // ------------------------------------------------------------------
    private fun derivePepperedPinKey(
        pin: CharArray,
        salt: ByteArray,
        iterations: Int
    ): SecretKey {
        if (!keystore.hasPepperKey()) {
            throw IllegalStateException("Pepper key ausente no Keystore")
        }
        val pbkdf2Bytes = Crypto.deriveBytes(pin, salt, iterations)
        try {
            val peppered = keystore.computePepperHmac(pbkdf2Bytes)
            return SecretKeySpec(peppered, "AES").also { peppered.fill(0) }
        } finally {
            pbkdf2Bytes.fill(0)
        }
    }

    // ------------------------------------------------------------------
    // Publicação atômica + migração de entradas
    // ------------------------------------------------------------------
    private fun publishUnlocked(master: ByteArray, loaded: MutableList<VaultEntry>) {
        lockGuard.withLock {
            keyBytes?.fill(0)
            keyBytes = master.copyOf()
            entries = loaded
            _unlocked.value = true
        }
    }

    private fun decodeEntries(masterKey: SecretKey, env: VaultEnvelope): MutableList<VaultEntry> {
        val decrypted = Crypto.decrypt(masterKey, env.data.base64(), aadFor(env))
        return json.decodeFromString(
            ListSerializer(VaultEntry.serializer()),
            String(decrypted)
        ).toMutableList()
    }

    /**
     * Garante que toda entrada tenha `id` (UUID) e timestamps.
     * Se algo mudou, re-cifra `data` e persiste **antes** de publicar o
     * estado destrancado. Lança `IOException` se a gravação falhar —
     * nesse caso, o cofre não é destrancado (para não ficar em estado
     * inconsistente entre memória e disco).
     */
    private fun migrateEntriesIfNeeded(
        loaded: MutableList<VaultEntry>,
        masterKey: SecretKey,
        env: VaultEnvelope
    ) {
        val now = System.currentTimeMillis()
        var changed = false
        for (i in loaded.indices) {
            val e = loaded[i]
            var modified = e
            var thisChanged = false
            if (e.id.isEmpty()) {
                modified = modified.copy(id = UUID.randomUUID().toString())
                thisChanged = true
            }
            if (e.createdAt == 0L) {
                modified = modified.copy(createdAt = now)
                thisChanged = true
            }
            if (e.updatedAt == 0L) {
                modified = modified.copy(updatedAt = now)
                thisChanged = true
            }
            if (thisChanged) {
                loaded[i] = modified
                changed = true
            }
        }
        if (changed) {
            val body = json.encodeToString(ListSerializer(VaultEntry.serializer()), loaded)
            val cipher = Crypto.encrypt(masterKey, body.toByteArray(), aadFor(env))
            persistAtomicallyOrThrow(env.copy(data = cipher.toBase64()))
        }
    }

    // ------------------------------------------------------------------
    // Criação
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

        try {
            keystore.createPepperKey()
        } catch (t: Throwable) {
            pin.fill('\u0000'); passphrase.fill('\u0000')
            return UnlockResult.Failure(
                IllegalStateException(
                    "Dispositivo não suporta proteção de hardware do PIN. " +
                        "Use a frase-chave apenas.",
                    t
                )
            )
        }

        val master = Crypto.randomBytes(32)
        val masterKey = SecretKeySpec(master, "AES")
        val saltPin = Crypto.randomBytes(SecurityPolicy.SALT_LENGTH_BYTES)
        val saltPhrase = Crypto.randomBytes(SecurityPolicy.SALT_LENGTH_BYTES)

        val header = VaultEnvelope(
            version = 4,
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

        val kPin = derivePepperedPinKey(pin, saltPin, header.iterPin)
        val kPhrase = Crypto.derive(phraseStr.toCharArray(), saltPhrase, header.iterPhrase)

        val wrappedPin = Crypto.encrypt(kPin, master, aad)
        val wrappedPhrase = Crypto.encrypt(kPhrase, master, aad)

        val emptyJson = json.encodeToString(
            ListSerializer(VaultEntry.serializer()),
            emptyList<VaultEntry>()
        )
        val dataCipher = Crypto.encrypt(masterKey, emptyJson.toByteArray(), aad)

        val envelope = header.copy(
            wrappedKeyPin = wrappedPin.toBase64(),
            wrappedKeyPhrase = wrappedPhrase.toBase64(),
            data = dataCipher.toBase64()
        )

        // ✅ Se a gravação falhar, NÃO publica estado destrancado.
        try {
            persistAtomicallyOrThrow(envelope)
        } catch (e: IOException) {
            master.fill(0)
            pin.fill('\u0000'); passphrase.fill('\u0000')
            return UnlockResult.Failure(e)
        }

        publishUnlocked(master, mutableListOf())
        master.fill(0)
        pin.fill('\u0000'); passphrase.fill('\u0000')
        return UnlockResult.Success
    }

    // ------------------------------------------------------------------
    // Desbloqueio por PIN
    // ------------------------------------------------------------------
    fun unlockPin(pin: CharArray): UnlockResult {
        try {
            val env = readEnvelope() ?: return UnlockResult.NoVault
            if (!SecurityPolicy.validateIterations(env.iterPin)) {
                return UnlockResult.CorruptedVault
            }
            val kPin: SecretKey = if (env.version >= 4) {
                if (!keystore.hasPepperKey()) return UnlockResult.NoPepper
                derivePepperedPinKey(pin, env.saltPin.base64(), env.iterPin)
            } else {
                return UnlockResult.LegacyVaultNoPepper
            }
            val master = Crypto.decrypt(kPin, env.wrappedKeyPin.base64(), aadFor(env))
            val masterKey = SecretKeySpec(master, "AES")

            val loaded = try {
                decodeEntries(masterKey, env)
            } catch (t: Throwable) {
                master.fill(0)
                return UnlockResult.CorruptedVault
            }

            // Pode lançar IOException se a migração não puder ser gravada.
            migrateEntriesIfNeeded(loaded, masterKey, env)
            publishUnlocked(master, loaded)
            master.fill(0)
            return UnlockResult.Success
        } catch (e: javax.crypto.AEADBadTagException) {
            return UnlockResult.WrongCredential
        } catch (e: IllegalArgumentException) {
            return UnlockResult.CorruptedVault
        } catch (e: IllegalStateException) {
            return UnlockResult.NoPepper
        } catch (e: GeneralSecurityException) {
            return UnlockResult.WrongCredential
        } catch (e: Exception) {
            return UnlockResult.Failure(e)
        } finally {
            pin.fill('\u0000')
        }
    }

    // ------------------------------------------------------------------
    // Desbloqueio por frase
    // ------------------------------------------------------------------
    fun unlockPhrase(phrase: CharArray): UnlockResult {
        try {
            val env = readEnvelope() ?: return UnlockResult.NoVault
            if (!SecurityPolicy.validateIterations(env.iterPhrase)) {
                return UnlockResult.CorruptedVault
            }
            val normalized = SecurityPolicy.normalizePassphrase(String(phrase))
            val kPh = Crypto.derive(normalized.toCharArray(), env.saltPhrase.base64(), env.iterPhrase)
            val master = Crypto.decrypt(kPh, env.wrappedKeyPhrase.base64(), aadFor(env))
            val masterKey = SecretKeySpec(master, "AES")

            val loaded = try {
                decodeEntries(masterKey, env)
            } catch (t: Throwable) {
                master.fill(0)
                return UnlockResult.CorruptedVault
            }

            migrateEntriesIfNeeded(loaded, masterKey, env)
            publishUnlocked(master, loaded)
            master.fill(0)
            return UnlockResult.Success
        } catch (e: javax.crypto.AEADBadTagException) {
            return UnlockResult.WrongCredential
        } catch (e: IllegalArgumentException) {
            return UnlockResult.CorruptedVault
        } catch (e: GeneralSecurityException) {
            return UnlockResult.WrongCredential
        } catch (e: Exception) {
            return UnlockResult.Failure(e)
        } finally {
            phrase.fill('\u0000')
        }
    }

    // ------------------------------------------------------------------
    // Re-wrap do PIN
    // ------------------------------------------------------------------
    fun rewrapPinWithCurrentMaster(newPin: CharArray): UnlockResult {
        val master = lockGuard.withLock { keyBytes?.copyOf() }
            ?: return UnlockResult.Failure(IllegalStateException("Cofre trancado"))
        try {
            if (!SecurityPolicy.isValidPin(String(newPin))) return UnlockResult.WrongCredential
            keystore.createPepperKey()
            val env = readEnvelope() ?: return UnlockResult.NoVault

            val newSaltPin = Crypto.randomBytes(SecurityPolicy.SALT_LENGTH_BYTES)
            val newHeader = env.copy(saltPin = newSaltPin.toBase64(), version = 4)
            val aad = aadFor(newHeader)

            val kPin = derivePepperedPinKey(newPin, newSaltPin, newHeader.iterPin)
            val wrappedPin = Crypto.encrypt(kPin, master, aad)

            val dataPlain = Crypto.decrypt(key(), env.data.base64(), aadFor(env))
            val dataCipher = Crypto.encrypt(key(), dataPlain, aad)

            persistAtomicallyOrThrow(
                newHeader.copy(
                    wrappedKeyPin = wrappedPin.toBase64(),
                    data = dataCipher.toBase64()
                )
            )
            return UnlockResult.Success
        } catch (t: Throwable) {
            return UnlockResult.Failure(t)
        } finally {
            master.fill(0)
            newPin.fill('\u0000')
        }
    }

    // ------------------------------------------------------------------
    // Biometria
    // ------------------------------------------------------------------
    fun enrollBiometric(cipher: Cipher): UnlockResult {
        val master = lockGuard.withLock { keyBytes?.copyOf() }
            ?: return UnlockResult.Failure(IllegalStateException("Cofre trancado"))
        try {
            val env = readEnvelope() ?: return UnlockResult.NoVault
            val aad = aadFor(env)
            cipher.updateAAD(aad)
            val ciphertext = cipher.doFinal(master)
            val wrapped = cipher.iv + ciphertext
            persistAtomicallyOrThrow(env.copy(wrappedKeyKeystore = wrapped.toBase64()))
            return UnlockResult.Success
        } catch (t: Throwable) {
            return UnlockResult.Failure(t)
        } finally {
            master.fill(0)
        }
    }

    fun hasBiometricEnrollment(): Boolean =
        readEnvelope()?.wrappedKeyKeystore != null

    fun getBiometricIv(): ByteArray? {
        val env = readEnvelope() ?: return null
        val wrapped = env.wrappedKeyKeystore?.let {
            runCatching { it.base64() }.getOrNull()
        } ?: return null
        return if (wrapped.size >= 12) wrapped.copyOfRange(0, 12) else null
    }

    fun disableBiometric(): UnlockResult = try {
        val env = readEnvelope() ?: return UnlockResult.NoVault
        persistAtomicallyOrThrow(env.copy(wrappedKeyKeystore = null))
        UnlockResult.Success
    } catch (t: Throwable) {
        UnlockResult.Failure(t)
    }

    fun unlockWithKeystoreCipher(cipher: Cipher): UnlockResult {
        return try {
            val env = readEnvelope() ?: return UnlockResult.NoVault
            val wrapped = env.wrappedKeyKeystore?.base64()
                ?: return UnlockResult.CorruptedVault
            if (wrapped.size <= 12) return UnlockResult.CorruptedVault

            val aad = aadFor(env)
            cipher.updateAAD(aad)
            val master = cipher.doFinal(wrapped, 12, wrapped.size - 12)
            val masterKey = SecretKeySpec(master, "AES")

            val loaded = try {
                decodeEntries(masterKey, env)
            } catch (t: Throwable) {
                master.fill(0)
                return UnlockResult.CorruptedVault
            }

            migrateEntriesIfNeeded(loaded, masterKey, env)
            publishUnlocked(master, loaded)
            master.fill(0)
            UnlockResult.Success
        } catch (e: GeneralSecurityException) {
            UnlockResult.WrongCredential
        } catch (e: Exception) {
            UnlockResult.Failure(e)
        }
    }

    // ------------------------------------------------------------------
    // CRUD — copy-and-swap + propagação de erro via Result
    // ------------------------------------------------------------------
    fun getEntries(): List<VaultEntry> = lockGuard.withLock { entries.toList() }

    /**
     * Adiciona uma entrada. Em caso de falha de gravação, `entries`
     * permanece inalterada e `Result.failure` carrega a causa.
     */
    fun addEntry(name: String, user: String, pass: String): Result<VaultEntry> =
        lockGuard.withLock {
            try {
                val now = System.currentTimeMillis()
                val entry = VaultEntry(
                    id = UUID.randomUUID().toString(),
                    name = name.trim(),
                    user = user.trim(),
                    pass = pass,
                    createdAt = now,
                    updatedAt = now
                )
                val newList = entries + entry
                persistEntriesOrThrow(newList)
                entries = newList.toMutableList()
                Result.success(entry)
            } catch (t: Throwable) {
                Result.failure(t)
            }
        }

    /**
     * Atualiza por `id`. `entries` só é alterada após a gravação bem-sucedida.
     */
    fun updateEntry(
        id: String,
        name: String,
        user: String,
        pass: String
    ): Result<Unit> = lockGuard.withLock {
        try {
            val idx = entries.indexOfFirst { it.id == id }
            if (idx < 0) {
                Result.failure(NoSuchElementException("Entrada não encontrada: $id"))
            } else {
                val updated = entries[idx].copy(
                    name = name.trim(),
                    user = user.trim(),
                    pass = pass,
                    updatedAt = System.currentTimeMillis()
                )
                val newList = entries.toMutableList().also { it[idx] = updated }
                persistEntriesOrThrow(newList)
                entries = newList
                Result.success(Unit)
            }
        } catch (t: Throwable) {
            Result.failure(t)
        }
    }

    /**
     * Remove por `id`. Idempotente: se não existir, `Success(Unit)`.
     */
    fun deleteEntry(id: String): Result<Unit> = lockGuard.withLock {
        try {
            if (entries.none { it.id == id }) {
                Result.success(Unit)  // já não existe — nada a fazer
            } else {
                val newList = entries.filter { it.id != id }.toMutableList()
                persistEntriesOrThrow(newList)
                entries = newList
                Result.success(Unit)
            }
        } catch (t: Throwable) {
            Result.failure(t)
        }
    }

    // ------------------------------------------------------------------
    // Persistência — qualquer falha lança IOException
    // ------------------------------------------------------------------
    /**
     * Serializa `newList`, cifra e grava. NÃO altera `entries`.
     * Lança `IOException` em qualquer falha (leitura, cifra, gravação).
     */
    private fun persistEntriesOrThrow(newList: List<VaultEntry>) {
        val env = readEnvelope()
            ?: throw IOException("Envelope do cofre não encontrado: ${vaultFile.absolutePath}")
        val body = json.encodeToString(ListSerializer(VaultEntry.serializer()), newList)
        val cipher = Crypto.encrypt(key(), body.toByteArray(), aadFor(env))
        persistAtomicallyOrThrow(env.copy(data = cipher.toBase64()))
    }

    private fun persistAtomicallyOrThrow(env: VaultEnvelope) {
        val parent = vaultFile.parentFile
            ?: throw IOException("Diretório do cofre inválido: ${vaultFile.absolutePath}")
        val tmp = File(parent, "${vaultFile.name}.tmp")
        val bak = File(parent, "${vaultFile.name}.bak")

        // 1) Escreve tmp com fsync
        try {
            FileOutputStream(tmp).use { fos ->
                fos.write(json.encodeToString(VaultEnvelope.serializer(), env).toByteArray())
                fos.flush()
                fos.fd.sync()
            }
        } catch (e: Exception) {
            runCatching { tmp.delete() }
            throw IOException("Falha ao escrever arquivo temporário: ${tmp.absolutePath}", e)
        }

        // 2) Backup do atual
        if (vaultFile.exists()) {
            try {
                vaultFile.copyTo(bak, overwrite = true)
            } catch (e: Exception) {
                runCatching { tmp.delete() }
                throw IOException("Falha ao criar backup: ${bak.absolutePath}", e)
            }
        }

        // 3) Substitui (rename ou copy+delete em cross-device)
        if (!tmp.renameTo(vaultFile)) {
            try {
                tmp.copyTo(vaultFile, overwrite = true)
                tmp.delete()
            } catch (e: Exception) {
                runCatching { tmp.delete() }
                throw IOException("Falha ao substituir vault.json: ${vaultFile.absolutePath}", e)
            }
        }

        // 4) Verificação final
        if (!vaultFile.exists()) {
            throw IOException("vault.json não existe após gravação: ${vaultFile.absolutePath}")
        }
        _exists.value = true
    }

    // ------------------------------------------------------------------
    // Chave
    // ------------------------------------------------------------------
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
    // AAD
    // ------------------------------------------------------------------
    private fun aadFor(env: VaultEnvelope): ByteArray =
        "v=${env.version}|ip=${env.iterPin}|iph=${env.iterPhrase}|sp=${env.saltPin}|sph=${env.saltPhrase}"
            .toByteArray(Charsets.UTF_8)

    private fun readEnvelope(): VaultEnvelope? {
        if (!vaultFile.exists()) return null
        return try {
            json.decodeFromString(VaultEnvelope.serializer(), vaultFile.readText())
        } catch (t: Throwable) {
            null
        }
    }
}
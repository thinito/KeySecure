package com.example.KeySecure

import android.os.Build
import com.example.KeySecure.crypto.Crypto
import com.example.KeySecure.crypto.IKeystore
import com.example.KeySecure.crypto.KeystoreManager
import com.example.KeySecure.data.EntryItem
import com.example.KeySecure.data.SecurityPolicy
import com.example.KeySecure.data.VaultEnvelope
import com.example.KeySecure.data.VaultEntry
import com.example.KeySecure.util.base64
import com.example.KeySecure.util.toBase64
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
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
    object NoPepper : UnlockResult()
    object LegacyVaultNoPepper : UnlockResult()
    object Aborted : UnlockResult()
    object RollbackDetected : UnlockResult()

    /** Cofre já existe e é válido; `create()` recusou sobrescrever. */
    object VaultAlreadyExists : UnlockResult()

    data class Failure(val cause: Throwable) : UnlockResult()
}

private sealed class EnvelopeResult {
    object Missing : EnvelopeResult()
    data class Corrupt(val cause: Throwable) : EnvelopeResult()
    data class Ok(val envelope: VaultEnvelope) : EnvelopeResult()
}

class Vault(
    private val vaultFile: File,
    private val keystore: IKeystore = KeystoreManager()
) {

    private val lockGuard = ReentrantLock()

    private val metaFile: File = File(vaultFile.parentFile, "${vaultFile.name}.meta")

    @Volatile
    private var generation: Long = 0L

    @Volatile
    private var keyBytes: ByteArray? = null

    @Volatile
    private var entries: List<VaultEntry> = emptyList()

    private val _unlocked = MutableStateFlow(false)
    val unlocked: StateFlow<Boolean> = _unlocked.asStateFlow()

    private val _exists = MutableStateFlow(vaultFile.exists())
    val exists: StateFlow<Boolean> = _exists.asStateFlow()

    private val json = Json {
        ignoreUnknownKeys = true
        prettyPrint = false
        encodeDefaults = true
    }

    fun fileExists(): Boolean = vaultFile.exists()
    fun keystoreManager(): IKeystore = keystore

    // ------------------------------------------------------------------
    // AAD com separação de domínio
    // ------------------------------------------------------------------
    private fun aadFor(env: VaultEnvelope, role: String, counter: Long = 0L): ByteArray =
        "$role|v=${env.version}|c=$counter|ip=${env.iterPin}|iph=${env.iterPhrase}|sp=${env.saltPin}|sph=${env.saltPhrase}"
            .toByteArray(Charsets.UTF_8)

    // ------------------------------------------------------------------
    // Geração / publicação
    // ------------------------------------------------------------------
    private fun captureGeneration(): Long = lockGuard.withLock { generation }

    private fun publishUnlocked(
        expectedGen: Long,
        master: ByteArray,
        loaded: List<VaultEntry>
    ): Boolean = lockGuard.withLock {
        if (generation != expectedGen) return@withLock false
        keyBytes?.fill(0)
        keyBytes = master.copyOf()
        entries = loaded
        _unlocked.value = true
        true
    }

    fun lock() = lockGuard.withLock {
        generation++
        keyBytes?.fill(0)
        keyBytes = null
        entries = emptyList()
        _unlocked.value = false
    }

    private fun key(): SecretKey {
        val b = keyBytes ?: error("Cofre trancado")
        return SecretKeySpec(b, "AES")
    }

    // ------------------------------------------------------------------
    // Leitura do envelope
    // ------------------------------------------------------------------
    private fun readEnvelope(): EnvelopeResult {
        if (!vaultFile.exists()) return EnvelopeResult.Missing
        return try {
            val text = vaultFile.readText()
            val env = json.decodeFromString(VaultEnvelope.serializer(), text)
            if (env.version < VaultEnvelope.MIN_SUPPORTED_VERSION ||
                env.version > VaultEnvelope.CURRENT_VERSION
            ) {
                EnvelopeResult.Corrupt(
                    IllegalArgumentException("Versão não suportada: ${env.version}")
                )
            } else {
                EnvelopeResult.Ok(env)
            }
        } catch (t: Throwable) {
            EnvelopeResult.Corrupt(t)
        }
    }

    // ------------------------------------------------------------------
    // Meta counter (rollback)
    // ------------------------------------------------------------------
    private fun readLastSeenCounterLocked(): Long {
        if (!metaFile.exists()) return 0L
        return runCatching { metaFile.readText().trim().toLong() }.getOrDefault(0L)
    }

    private fun writeLastSeenCounterLocked(counter: Long) {
        if (counter <= 0L) return
        runCatching {
            val tmp = File(metaFile.parentFile, "${metaFile.name}.tmp")
            tmp.writeText(counter.toString())
            if (!tmp.renameTo(metaFile)) tmp.delete()
        }
    }

    private fun onPersistSuccess(newCounter: Long) = lockGuard.withLock {
        val stored = readLastSeenCounterLocked()
        if (newCounter > stored) writeLastSeenCounterLocked(newCounter)
    }

    // ------------------------------------------------------------------
    // Derivação endurecida
    // ------------------------------------------------------------------
    private fun derivePepperedPinKey(pin: CharArray, salt: ByteArray, iterations: Int): SecretKey {
        if (!keystore.hasPepperKey()) throw IllegalStateException("Pepper key ausente")
        val pbkdf2Bytes = Crypto.deriveBytes(pin, salt, iterations)
        try {
            val peppered = keystore.computePepperHmac(pbkdf2Bytes)
            return SecretKeySpec(peppered, "AES").also { peppered.fill(0) }
        } finally {
            pbkdf2Bytes.fill(0)
        }
    }

    // ------------------------------------------------------------------
    // Decode + migração
    // ------------------------------------------------------------------
    private fun decodeEntries(masterKey: SecretKey, env: VaultEnvelope): List<VaultEntry> {
        val decrypted = Crypto.decrypt(
            masterKey, env.data.base64(), aadFor(env, "data", env.counter)
        )
        return try {
            json.decodeFromString(
                ListSerializer(VaultEntry.serializer()),
                String(decrypted)
            )
        } finally {
            decrypted.fill(0)
        }
    }

    private fun migrateEntriesIfNeeded(
        loaded: List<VaultEntry>,
        masterKey: SecretKey,
        env: VaultEnvelope
    ): Pair<List<VaultEntry>, VaultEnvelope> {
        val now = System.currentTimeMillis()
        val migrated = loaded.map { e ->
            e.copy(
                id = e.id.ifEmpty { UUID.randomUUID().toString() },
                createdAt = e.createdAt.takeIf { it != 0L } ?: now,
                updatedAt = e.updatedAt.takeIf { it != 0L } ?: now
            )
        }
        if (migrated == loaded) return loaded to env

        val newCounter = env.counter + 1
        val newEnv = env.copy(counter = newCounter)
        val body = json.encodeToString(ListSerializer(VaultEntry.serializer()), migrated)
        val cipher = Crypto.encrypt(masterKey, body.toByteArray(), aadFor(newEnv, "data", newCounter))
        persistAtomicallyOrThrow(newEnv.copy(data = cipher.toBase64()))
        return migrated to newEnv
    }

    // ------------------------------------------------------------------
    // Criação
    // ------------------------------------------------------------------
    fun create(pin: CharArray, passphrase: CharArray): UnlockResult {
        try {
            // 1) Recusa se já existe QUALQUER arquivo em vaultFile.
            //    Se o arquivo existir mas estiver corrompido, o usuário precisa
            //    apagá-lo manualmente (ou usar "esqueci tudo") — não sobrescrevemos
            //    silenciosamente para não destruir dados potencialmente recuperáveis.
            if (vaultFile.exists()) {
                return UnlockResult.VaultAlreadyExists
            }

            // 2) Validações (não lançam: isStrongPin / isStrongPassphrase são puras)
            if (!SecurityPolicy.isStrongPin(pin)) {
                return UnlockResult.WrongCredential
            }

            val normalizedPhrase = SecurityPolicy.normalizePassphrase(passphrase)
            passphrase.fill('\u0000')
            if (!SecurityPolicy.isStrongPassphrase(normalizedPhrase)) {
                return UnlockResult.WrongCredential
            }

            // 3) Pepper HMAC no Keystore
            try {
                keystore.createPepperKey()
            } catch (t: Throwable) {
                return UnlockResult.Failure(
                    IllegalStateException(
                        "Dispositivo não suporta proteção de hardware do PIN.",
                        t
                    )
                )
            }

            val startGen = captureGeneration()
            val master = Crypto.randomBytes(32)
            val masterKey = SecretKeySpec(master, "AES")
            val saltPin = Crypto.randomBytes(SecurityPolicy.SALT_LENGTH_BYTES)
            val saltPhrase = Crypto.randomBytes(SecurityPolicy.SALT_LENGTH_BYTES)

            val header = VaultEnvelope(
                version = VaultEnvelope.CURRENT_VERSION,
                counter = 1L,
                iterPin = SecurityPolicy.PBKDF2_ITERATIONS,
                iterPhrase = SecurityPolicy.PBKDF2_ITERATIONS,
                saltPin = saltPin.toBase64(),
                saltPhrase = saltPhrase.toBase64(),
                wrappedKeyPin = "",
                wrappedKeyPhrase = "",
                wrappedKeyKeystore = null,
                data = ""
            )

            // 4) Derivações — cada uma pode lançar GeneralSecurityException.
            //    O catch externo converte em Failure.
            val kPin = derivePepperedPinKey(pin, saltPin, header.iterPin)

            val phraseChars = normalizedPhrase.toCharArray()
            val kPhrase: SecretKey = try {
                Crypto.derive(phraseChars, saltPhrase, header.iterPhrase)
            } finally {
                phraseChars.fill('\u0000')
            }

            val wrappedPin = Crypto.encrypt(kPin, master, aadFor(header, "pin"))
            val wrappedPhrase = Crypto.encrypt(kPhrase, master, aadFor(header, "phrase"))

            val emptyJson = json.encodeToString(
                ListSerializer(VaultEntry.serializer()),
                emptyList<VaultEntry>()
            )
            val dataCipher = Crypto.encrypt(
                masterKey,
                emptyJson.toByteArray(),
                aadFor(header, "data", header.counter)
            )

            val envelope = header.copy(
                wrappedKeyPin = wrappedPin.toBase64(),
                wrappedKeyPhrase = wrappedPhrase.toBase64(),
                data = dataCipher.toBase64()
            )

            // 5) Gravação — IOException vira Failure, não propaga.
            try {
                persistAtomicallyOrThrow(envelope)
            } catch (e: IOException) {
                master.fill(0)
                return UnlockResult.Failure(e)
            }

            // 6) Publicação atômica
            val published = publishUnlocked(startGen, master, emptyList())
            master.fill(0)

            return if (published) UnlockResult.Success else UnlockResult.Aborted
        } catch (t: Throwable) {
            // ✅ Rede de segurança: qualquer exceção não tratada acima
            // (GeneralSecurityException, OOM, etc.) vira Failure em vez de
            // derrubar o app. `finally` garante a limpeza dos buffers.
            return UnlockResult.Failure(t)
        } finally {
            pin.fill('\u0000')
            passphrase.fill('\u0000')
        }
    }

    // ------------------------------------------------------------------
    // Desbloqueio
    // ------------------------------------------------------------------
    fun unlockPin(pin: CharArray): UnlockResult {
        val startGen = captureGeneration()
        try {
            val env = when (val r = readEnvelope()) {
                is EnvelopeResult.Missing -> return UnlockResult.NoVault
                is EnvelopeResult.Corrupt -> return UnlockResult.CorruptedVault
                is EnvelopeResult.Ok -> r.envelope
            }
            if (!SecurityPolicy.validateIterations(env.iterPin)) {
                return UnlockResult.CorruptedVault
            }

            val lastSeen = lockGuard.withLock { readLastSeenCounterLocked() }
            if (env.counter < lastSeen) return UnlockResult.RollbackDetected

            val kPin: SecretKey = if (env.version >= 4) {
                if (!keystore.hasPepperKey()) return UnlockResult.NoPepper
                derivePepperedPinKey(pin, env.saltPin.base64(), env.iterPin)
            } else {
                return UnlockResult.LegacyVaultNoPepper
            }

            if (lockGuard.withLock { generation != startGen }) {
                return UnlockResult.Aborted
            }

            val master = Crypto.decrypt(kPin, env.wrappedKeyPin.base64(), aadFor(env, "pin"))
            val masterKey = SecretKeySpec(master, "AES")

            val loaded0 = try {
                decodeEntries(masterKey, env)
            } catch (t: Throwable) {
                master.fill(0)
                return UnlockResult.CorruptedVault
            }

            val (loaded, finalEnv) = migrateEntriesIfNeeded(loaded0, masterKey, env)
            val published = publishUnlocked(startGen, master, loaded)
            master.fill(0)

            return if (published) {
                onPersistSuccess(finalEnv.counter)
                UnlockResult.Success
            } else {
                UnlockResult.Aborted
            }
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

    fun unlockPhrase(phrase: CharArray): UnlockResult {
        val startGen = captureGeneration()
        try {
            val env = when (val r = readEnvelope()) {
                is EnvelopeResult.Missing -> return UnlockResult.NoVault
                is EnvelopeResult.Corrupt -> return UnlockResult.CorruptedVault
                is EnvelopeResult.Ok -> r.envelope
            }
            if (!SecurityPolicy.validateIterations(env.iterPhrase)) {
                return UnlockResult.CorruptedVault
            }

            val lastSeen = lockGuard.withLock { readLastSeenCounterLocked() }
            if (env.counter < lastSeen) return UnlockResult.RollbackDetected

            val normalized = SecurityPolicy.normalizePassphrase(phrase)
            phrase.fill('\u0000')
            val phraseChars = normalized.toCharArray()
            val kPh: SecretKey = try {
                Crypto.derive(phraseChars, env.saltPhrase.base64(), env.iterPhrase)
            } finally {
                phraseChars.fill('\u0000')
            }

            if (lockGuard.withLock { generation != startGen }) {
                return UnlockResult.Aborted
            }

            val master = Crypto.decrypt(kPh, env.wrappedKeyPhrase.base64(), aadFor(env, "phrase"))
            val masterKey = SecretKeySpec(master, "AES")

            val loaded0 = try {
                decodeEntries(masterKey, env)
            } catch (t: Throwable) {
                master.fill(0)
                return UnlockResult.CorruptedVault
            }

            val (loaded, finalEnv) = migrateEntriesIfNeeded(loaded0, masterKey, env)
            val published = publishUnlocked(startGen, master, loaded)
            master.fill(0)

            return if (published) {
                onPersistSuccess(finalEnv.counter)
                UnlockResult.Success
            } else {
                UnlockResult.Aborted
            }
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

    fun unlockWithKeystoreCipher(cipher: Cipher): UnlockResult {
        val startGen = captureGeneration()
        return try {
            val env = when (val r = readEnvelope()) {
                is EnvelopeResult.Missing -> return UnlockResult.NoVault
                is EnvelopeResult.Corrupt -> return UnlockResult.CorruptedVault
                is EnvelopeResult.Ok -> r.envelope
            }
            val wrapped = env.wrappedKeyKeystore?.base64() ?: return UnlockResult.CorruptedVault
            if (wrapped.size <= 12) return UnlockResult.CorruptedVault

            val lastSeen = lockGuard.withLock { readLastSeenCounterLocked() }
            if (env.counter < lastSeen) return UnlockResult.RollbackDetected
            if (lockGuard.withLock { generation != startGen }) return UnlockResult.Aborted

            cipher.updateAAD(aadFor(env, "keystore"))
            val master = cipher.doFinal(wrapped, 12, wrapped.size - 12)
            val masterKey = SecretKeySpec(master, "AES")

            val loaded0 = try {
                decodeEntries(masterKey, env)
            } catch (t: Throwable) {
                master.fill(0)
                return UnlockResult.CorruptedVault
            }

            val (loaded, finalEnv) = migrateEntriesIfNeeded(loaded0, masterKey, env)
            val published = publishUnlocked(startGen, master, loaded)
            master.fill(0)

            if (published) {
                onPersistSuccess(finalEnv.counter)
                UnlockResult.Success
            } else {
                UnlockResult.Aborted
            }
        } catch (e: GeneralSecurityException) {
            UnlockResult.WrongCredential
        } catch (e: Exception) {
            UnlockResult.Failure(e)
        }
    }

    // ------------------------------------------------------------------
    // Biometria
    // ------------------------------------------------------------------
    fun enrollBiometric(cipher: Cipher): UnlockResult {
        val master = lockGuard.withLock { keyBytes?.copyOf() }
            ?: return UnlockResult.Failure(IllegalStateException("Cofre trancado"))
        return try {
            enrollBiometricLocked(master, cipher)
        } catch (t: Throwable) {
            UnlockResult.Failure(t)
        } finally {
            master.fill(0)
        }
    }

    private fun enrollBiometricLocked(master: ByteArray, cipher: Cipher): UnlockResult {
        val masterKey = SecretKeySpec(master, "AES")
        val env = when (val r = readEnvelope()) {
            is EnvelopeResult.Missing -> return UnlockResult.NoVault
            is EnvelopeResult.Corrupt -> return UnlockResult.CorruptedVault
            is EnvelopeResult.Ok -> r.envelope
        }
        val newCounter = env.counter + 1
        val newEnv = env.copy(counter = newCounter)

        cipher.updateAAD(aadFor(newEnv, "keystore"))
        val ciphertext = cipher.doFinal(master)
        val wrapped = cipher.iv + ciphertext

        val dataPlain = Crypto.decrypt(masterKey, env.data.base64(), aadFor(env, "data", env.counter))
        val dataCipher = Crypto.encrypt(masterKey, dataPlain, aadFor(newEnv, "data", newCounter))
        dataPlain.fill(0)

        persistAtomicallyOrThrow(
            newEnv.copy(
                wrappedKeyKeystore = wrapped.toBase64(),
                data = dataCipher.toBase64()
            )
        )
        return UnlockResult.Success
    }

    fun hasBiometricEnrollment(): Boolean {
        val r = readEnvelope()
        return r is EnvelopeResult.Ok && r.envelope.wrappedKeyKeystore != null
    }

    fun getBiometricIv(): ByteArray? {
        val r = readEnvelope() as? EnvelopeResult.Ok ?: return null
        val wrapped = r.envelope.wrappedKeyKeystore
            ?.let { runCatching { it.base64() }.getOrNull() }
            ?: return null
        return if (wrapped.size >= 12) wrapped.copyOfRange(0, 12) else null
    }

    fun disableBiometric(): UnlockResult {
        val master = lockGuard.withLock { keyBytes?.copyOf() }
            ?: return UnlockResult.Failure(IllegalStateException("Cofre trancado"))
        return try {
            disableBiometricLocked(master)
        } catch (t: Throwable) {
            UnlockResult.Failure(t)
        } finally {
            master.fill(0)
        }
    }

    private fun disableBiometricLocked(master: ByteArray): UnlockResult {
        val masterKey = SecretKeySpec(master, "AES")
        val env = when (val r = readEnvelope()) {
            is EnvelopeResult.Missing -> return UnlockResult.NoVault
            is EnvelopeResult.Corrupt -> return UnlockResult.CorruptedVault
            is EnvelopeResult.Ok -> r.envelope
        }
        val newCounter = env.counter + 1
        val newEnv = env.copy(counter = newCounter, wrappedKeyKeystore = null)

        val dataPlain = Crypto.decrypt(masterKey, env.data.base64(), aadFor(env, "data", env.counter))
        val dataCipher = Crypto.encrypt(masterKey, dataPlain, aadFor(newEnv, "data", newCounter))
        dataPlain.fill(0)

        persistAtomicallyOrThrow(newEnv.copy(data = dataCipher.toBase64()))
        return UnlockResult.Success
    }

    // ------------------------------------------------------------------
    // Troca de credenciais
    // ------------------------------------------------------------------
    fun changePin(currentPin: CharArray, newPin: CharArray): UnlockResult {
        val master = lockGuard.withLock { keyBytes?.copyOf() }
            ?: return UnlockResult.Failure(IllegalStateException("Cofre trancado"))
        return try {
            changePinLocked(master, currentPin, newPin)
        } catch (t: Throwable) {
            UnlockResult.Failure(t)
        } finally {
            master.fill(0)
            currentPin.fill('\u0000')
            newPin.fill('\u0000')
        }
    }

    private fun changePinLocked(
        master: ByteArray,
        currentPin: CharArray,
        newPin: CharArray
    ): UnlockResult {
        if (!SecurityPolicy.isStrongPin(newPin)) return UnlockResult.WrongCredential

        val env = when (val r = readEnvelope()) {
            is EnvelopeResult.Missing -> return UnlockResult.NoVault
            is EnvelopeResult.Corrupt -> return UnlockResult.CorruptedVault
            is EnvelopeResult.Ok -> r.envelope
        }
        if (env.version < 4) return UnlockResult.LegacyVaultNoPepper
        if (!keystore.hasPepperKey()) return UnlockResult.NoPepper

        val masterKey = SecretKeySpec(master, "AES")
        val kCurrent = derivePepperedPinKey(currentPin, env.saltPin.base64(), env.iterPin)
        try {
            val test = Crypto.decrypt(kCurrent, env.wrappedKeyPin.base64(), aadFor(env, "pin"))
            val ok = test.contentEquals(master)
            test.fill(0)
            if (!ok) return UnlockResult.WrongCredential
        } catch (e: GeneralSecurityException) {
            return UnlockResult.WrongCredential
        }

        val newCounter = env.counter + 1
        val newEnv = env.copy(counter = newCounter)
        val kNew = derivePepperedPinKey(newPin, env.saltPin.base64(), env.iterPin)
        val newWrapped = Crypto.encrypt(kNew, master, aadFor(newEnv, "pin"))

        val dataPlain = Crypto.decrypt(masterKey, env.data.base64(), aadFor(env, "data", env.counter))
        val dataCipher = Crypto.encrypt(masterKey, dataPlain, aadFor(newEnv, "data", newCounter))
        dataPlain.fill(0)

        persistAtomicallyOrThrow(
            newEnv.copy(
                wrappedKeyPin = newWrapped.toBase64(),
                data = dataCipher.toBase64()
            )
        )
        return UnlockResult.Success
    }

    fun changePassphrase(currentPhrase: CharArray, newPhrase: CharArray): UnlockResult {
        val master = lockGuard.withLock { keyBytes?.copyOf() }
            ?: return UnlockResult.Failure(IllegalStateException("Cofre trancado"))
        return try {
            changePassphraseLocked(master, currentPhrase, newPhrase)
        } catch (t: Throwable) {
            UnlockResult.Failure(t)
        } finally {
            master.fill(0)
            currentPhrase.fill('\u0000')
            newPhrase.fill('\u0000')
        }
    }

    private fun changePassphraseLocked(
        master: ByteArray,
        currentPhrase: CharArray,
        newPhrase: CharArray
    ): UnlockResult {
        val normalizedNew = SecurityPolicy.normalizePassphrase(newPhrase)
        if (!SecurityPolicy.isStrongPassphrase(normalizedNew)) {
            return UnlockResult.WrongCredential
        }

        val env = when (val r = readEnvelope()) {
            is EnvelopeResult.Missing -> return UnlockResult.NoVault
            is EnvelopeResult.Corrupt -> return UnlockResult.CorruptedVault
            is EnvelopeResult.Ok -> r.envelope
        }

        val masterKey = SecretKeySpec(master, "AES")
        val normalizedCurrent = SecurityPolicy.normalizePassphrase(currentPhrase)
        val curChars = normalizedCurrent.toCharArray()
        val kCurrent: SecretKey = try {
            Crypto.derive(curChars, env.saltPhrase.base64(), env.iterPhrase)
        } finally {
            curChars.fill('\u0000')
        }
        try {
            val test = Crypto.decrypt(kCurrent, env.wrappedKeyPhrase.base64(), aadFor(env, "phrase"))
            val ok = test.contentEquals(master)
            test.fill(0)
            if (!ok) return UnlockResult.WrongCredential
        } catch (e: GeneralSecurityException) {
            return UnlockResult.WrongCredential
        }

        val newCounter = env.counter + 1
        val newEnv = env.copy(counter = newCounter)
        val newChars = normalizedNew.toCharArray()
        val kNew: SecretKey = try {
            Crypto.derive(newChars, env.saltPhrase.base64(), env.iterPhrase)
        } finally {
            newChars.fill('\u0000')
        }
        val newWrapped = Crypto.encrypt(kNew, master, aadFor(newEnv, "phrase"))

        val dataPlain = Crypto.decrypt(masterKey, env.data.base64(), aadFor(env, "data", env.counter))
        val dataCipher = Crypto.encrypt(masterKey, dataPlain, aadFor(newEnv, "data", newCounter))
        dataPlain.fill(0)

        persistAtomicallyOrThrow(
            newEnv.copy(
                wrappedKeyPhrase = newWrapped.toBase64(),
                data = dataCipher.toBase64()
            )
        )
        return UnlockResult.Success
    }

    fun needsIterationUpgrade(): Boolean {
        val r = readEnvelope() as? EnvelopeResult.Ok ?: return false
        if (r.envelope.version < 4) return false
        return r.envelope.iterPin < SecurityPolicy.PBKDF2_ITERATIONS ||
            r.envelope.iterPhrase < SecurityPolicy.PBKDF2_ITERATIONS
    }

    fun upgradeIterations(currentPin: CharArray, currentPhrase: CharArray): UnlockResult {
        val master = lockGuard.withLock { keyBytes?.copyOf() }
            ?: return UnlockResult.Failure(IllegalStateException("Cofre trancado"))
        return try {
            upgradeIterationsLocked(master, currentPin, currentPhrase)
        } catch (t: Throwable) {
            UnlockResult.Failure(t)
        } finally {
            master.fill(0)
            currentPin.fill('\u0000')
            currentPhrase.fill('\u0000')
        }
    }

    private fun upgradeIterationsLocked(
        master: ByteArray,
        currentPin: CharArray,
        currentPhrase: CharArray
    ): UnlockResult {
        val env = when (val r = readEnvelope()) {
            is EnvelopeResult.Missing -> return UnlockResult.NoVault
            is EnvelopeResult.Corrupt -> return UnlockResult.CorruptedVault
            is EnvelopeResult.Ok -> r.envelope
        }
        if (env.version < 4) return UnlockResult.LegacyVaultNoPepper
        if (!keystore.hasPepperKey()) return UnlockResult.NoPepper

        val masterKey = SecretKeySpec(master, "AES")

        val kPinOld = derivePepperedPinKey(currentPin, env.saltPin.base64(), env.iterPin)
        try {
            val t = Crypto.decrypt(kPinOld, env.wrappedKeyPin.base64(), aadFor(env, "pin"))
            val ok = t.contentEquals(master)
            t.fill(0)
            if (!ok) return UnlockResult.WrongCredential
        } catch (e: GeneralSecurityException) {
            return UnlockResult.WrongCredential
        }

        val normPhrase = SecurityPolicy.normalizePassphrase(currentPhrase)
        val phChars = normPhrase.toCharArray()
        val kPhOld: SecretKey = try {
            Crypto.derive(phChars, env.saltPhrase.base64(), env.iterPhrase)
        } finally {
            phChars.fill('\u0000')
        }
        try {
            val t = Crypto.decrypt(kPhOld, env.wrappedKeyPhrase.base64(), aadFor(env, "phrase"))
            val ok = t.contentEquals(master)
            t.fill(0)
            if (!ok) return UnlockResult.WrongCredential
        } catch (e: GeneralSecurityException) {
            return UnlockResult.WrongCredential
        }

        val dataPlain = Crypto.decrypt(masterKey, env.data.base64(), aadFor(env, "data", env.counter))

        val newSaltPin = Crypto.randomBytes(SecurityPolicy.SALT_LENGTH_BYTES)
        val newSaltPhrase = Crypto.randomBytes(SecurityPolicy.SALT_LENGTH_BYTES)
        val newCounter = env.counter + 1
        val newEnv = env.copy(
            counter = newCounter,
            iterPin = SecurityPolicy.PBKDF2_ITERATIONS,
            iterPhrase = SecurityPolicy.PBKDF2_ITERATIONS,
            saltPin = newSaltPin.toBase64(),
            saltPhrase = newSaltPhrase.toBase64(),
            wrappedKeyKeystore = null
        )

        val kPinNew = derivePepperedPinKey(currentPin, newSaltPin, newEnv.iterPin)
        val phChars2 = normPhrase.toCharArray()
        val kPhNew: SecretKey = try {
            Crypto.derive(phChars2, newSaltPhrase, newEnv.iterPhrase)
        } finally {
            phChars2.fill('\u0000')
        }

        val newWrappedPin = Crypto.encrypt(kPinNew, master, aadFor(newEnv, "pin"))
        val newWrappedPhrase = Crypto.encrypt(kPhNew, master, aadFor(newEnv, "phrase"))
        val newData = Crypto.encrypt(masterKey, dataPlain, aadFor(newEnv, "data", newCounter))
        dataPlain.fill(0)

        persistAtomicallyOrThrow(
            newEnv.copy(
                wrappedKeyPin = newWrappedPin.toBase64(),
                wrappedKeyPhrase = newWrappedPhrase.toBase64(),
                data = newData.toBase64()
            )
        )
        return UnlockResult.Success
    }

    // ------------------------------------------------------------------
    // CRUD
    // ------------------------------------------------------------------
    fun getEntrySummaries(): List<EntryItem> = lockGuard.withLock {
        entries.map { EntryItem(it.id, it.name, it.user) }
    }

    fun getEntryPasswordSnapshot(id: String): String? = lockGuard.withLock {
        entries.firstOrNull { it.id == id }?.pass
    }

    fun getEntries(): List<VaultEntry> = lockGuard.withLock { entries }

    fun addEntry(name: String, user: String, pass: String): Result<EntryItem> =
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
                entries = newList
                Result.success(EntryItem(entry.id, entry.name, entry.user))
            } catch (t: Throwable) {
                Result.failure(t)
            }
        }

    fun updateEntry(id: String, name: String, user: String, pass: String): Result<Unit> =
        lockGuard.withLock {
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

    fun deleteEntry(id: String): Result<Unit> = lockGuard.withLock {
        try {
            if (entries.none { it.id == id }) {
                Result.success(Unit)
            } else {
                val newList = entries.filter { it.id != id }
                persistEntriesOrThrow(newList)
                entries = newList
                Result.success(Unit)
            }
        } catch (t: Throwable) {
            Result.failure(t)
        }
    }

    // ------------------------------------------------------------------
    // Persistência
    // ------------------------------------------------------------------
    private fun persistEntriesOrThrow(newList: List<VaultEntry>) {
        val env = when (val r = readEnvelope()) {
            is EnvelopeResult.Ok -> r.envelope
            is EnvelopeResult.Missing ->
                throw IOException("Envelope ausente: ${vaultFile.absolutePath}")
            is EnvelopeResult.Corrupt ->
                throw IOException("Envelope ilegível", r.cause)
        }
        val newCounter = env.counter + 1
        val newEnv = env.copy(counter = newCounter)
        val body = json.encodeToString(ListSerializer(VaultEntry.serializer()), newList)
        val cipher = Crypto.encrypt(key(), body.toByteArray(), aadFor(newEnv, "data", newCounter))
        persistAtomicallyOrThrow(newEnv.copy(data = cipher.toBase64()))
    }

    private fun persistAtomicallyOrThrow(env: VaultEnvelope) {
        val parent = vaultFile.parentFile
            ?: throw IOException("Diretório inválido: ${vaultFile.absolutePath}")
        val tmp = File(parent, "${vaultFile.name}.tmp")

        try {
            FileOutputStream(tmp).use { fos ->
                fos.write(json.encodeToString(VaultEnvelope.serializer(), env).toByteArray())
                fos.flush()
                fos.fd.sync()
            }
        } catch (e: Exception) {
            runCatching { tmp.delete() }
            throw IOException("Falha ao escrever tmp: ${tmp.absolutePath}", e)
        }

        try {
            Files.move(
                tmp.toPath(),
                vaultFile.toPath(),
                StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING
            )
        } catch (e: AtomicMoveNotSupportedException) {
            try {
                Files.move(
                    tmp.toPath(),
                    vaultFile.toPath(),
                    StandardCopyOption.REPLACE_EXISTING
                )
            } catch (e2: Exception) {
                runCatching { tmp.delete() }
                throw IOException("Falha ao mover tmp: ${tmp.absolutePath}", e2)
            }
        } catch (e: NoClassDefFoundError) {
            try {
                if (vaultFile.exists() && !vaultFile.delete()) {
                    throw IOException("Falha ao remover vault.json antigo")
                }
                if (!tmp.renameTo(vaultFile)) {
                    throw IOException("Rename falhou: ${tmp.absolutePath}")
                }
            } catch (e2: Exception) {
                runCatching { tmp.delete() }
                throw IOException("Falha ao substituir vault.json", e2)
            }
        } catch (e: Exception) {
            runCatching { tmp.delete() }
            throw IOException("Falha ao mover tmp: ${tmp.absolutePath}", e)
        }

        runCatching { File(parent, "${vaultFile.name}.bak").delete() }

        if (!vaultFile.exists()) {
            throw IOException("vault.json ausente após gravação")
        }
        _exists.value = true
        onPersistSuccess(env.counter)
    }
}
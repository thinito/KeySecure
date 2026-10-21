package com.example.KeySecure

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
    object NoPepper : UnlockResult()
    object LegacyVaultNoPepper : UnlockResult()
    object Aborted : UnlockResult()
    data class Failure(val cause: Throwable) : UnlockResult()
}

private sealed class EnvelopeResult {
    object Missing : EnvelopeResult()
    data class Corrupt(val cause: Throwable, val source: String) : EnvelopeResult()
    data class Ok(val envelope: VaultEnvelope, val source: String) : EnvelopeResult()
}

class Vault(
    private val vaultFile: File,
    private val keystore: IKeystore = KeystoreManager()
) {

    private val lockGuard = ReentrantLock()

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

    private val json = Json { ignoreUnknownKeys = true; prettyPrint = false }

    fun fileExists(): Boolean = vaultFile.exists()
    fun keystoreManager(): IKeystore = keystore

    // ------------------------------------------------------------------
    // Geração / publicação atômica
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
    // Leitura do envelope + recuperação via .bak
    // ------------------------------------------------------------------
    private fun readEnvelope(): EnvelopeResult {
        val main = tryReadEnvelope(vaultFile)
        if (main is EnvelopeResult.Ok) return main

        val parent = vaultFile.parentFile ?: return main
        val bakFile = File(parent, "${vaultFile.name}.bak")
        val bak = tryReadEnvelope(bakFile)
        if (bak is EnvelopeResult.Ok) {
            runCatching {
                bakFile.copyTo(vaultFile, overwrite = true)
                _exists.value = true
            }
            return EnvelopeResult.Ok(bak.envelope, "bak")
        }
        return when {
            main is EnvelopeResult.Corrupt -> main
            bak is EnvelopeResult.Corrupt -> bak
            else -> EnvelopeResult.Missing
        }
    }

    private fun tryReadEnvelope(file: File): EnvelopeResult {
        if (!file.exists()) return EnvelopeResult.Missing
        return try {
            val text = file.readText()
            val env = json.decodeFromString(VaultEnvelope.serializer(), text)
            if (env.version !in MIN_SUPPORTED_VERSION..MAX_SUPPORTED_VERSION) {
                EnvelopeResult.Corrupt(
                    IllegalArgumentException("Versão não suportada: ${env.version}"),
                    file.name
                )
            } else EnvelopeResult.Ok(env, file.name)
        } catch (t: Throwable) {
            EnvelopeResult.Corrupt(t, file.name)
        }
    }

    // ------------------------------------------------------------------
    // Derivação endurecida por hardware
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
        val decrypted = Crypto.decrypt(masterKey, env.data.base64(), aadFor(env))
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
    ): List<VaultEntry> {
        val now = System.currentTimeMillis()
        val migrated = loaded.map { e ->
            e.copy(
                id = e.id.ifEmpty { UUID.randomUUID().toString() },
                createdAt = e.createdAt.takeIf { it != 0L } ?: now,
                updatedAt = e.updatedAt.takeIf { it != 0L } ?: now
            )
        }
        if (migrated == loaded) return loaded
        val body = json.encodeToString(ListSerializer(VaultEntry.serializer()), migrated)
        val cipher = Crypto.encrypt(masterKey, body.toByteArray(), aadFor(env))
        persistAtomicallyOrThrow(env.copy(data = cipher.toBase64()))
        return migrated
    }

    // ------------------------------------------------------------------
    // Criação — valida sobre CharArray, sem String(pin)
    // ------------------------------------------------------------------
    fun create(pin: CharArray, passphrase: CharArray): UnlockResult {
        try {
            if (vaultFile.exists()) {
                return UnlockResult.Failure(IllegalStateException("Cofre já existe"))
            }

            // ✅ PIN validado sobre CharArray — nenhuma String imutável criada.
            if (!SecurityPolicy.isStrongPin(pin)) {
                return UnlockResult.WrongCredential
            }

            // Frase: NFKC exige String; uma única cópia transitória.
            // A CharArray original é zerada imediatamente.
            val normalizedPhrase = SecurityPolicy.normalizePassphrase(passphrase)
            passphrase.fill('\u0000')

            if (!SecurityPolicy.isStrongPassphrase(normalizedPhrase)) {
                return UnlockResult.WrongCredential
            }

            try {
                keystore.createPepperKey()
            } catch (t: Throwable) {
                return UnlockResult.Failure(
                    IllegalStateException("Dispositivo não suporta proteção de hardware do PIN.", t)
                )
            }

            val startGen = captureGeneration()

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

            // Frase: CharArray temporária zerada em finally
            val phraseChars = normalizedPhrase.toCharArray()
            val kPhrase: SecretKey = try {
                Crypto.derive(phraseChars, saltPhrase, header.iterPhrase)
            } finally {
                phraseChars.fill('\u0000')
            }

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

            try {
                persistAtomicallyOrThrow(envelope)
            } catch (e: IOException) {
                return UnlockResult.Failure(e)
            }

            // ✅ master copiado para keyBytes dentro do lock; original zerado.
            val published = publishUnlocked(startGen, master, emptyList())
            master.fill(0)

            return if (published) UnlockResult.Success else UnlockResult.Aborted
        } finally {
            pin.fill('\u0000')
            passphrase.fill('\u0000')
        }
    }

    // ------------------------------------------------------------------
    // Desbloqueio por PIN
    // ------------------------------------------------------------------
    fun unlockPin(pin: CharArray): UnlockResult {
        val startGen = captureGeneration()
        try {
            val env = when (val r = readEnvelope()) {
                is EnvelopeResult.Missing -> return UnlockResult.NoVault
                is EnvelopeResult.Corrupt -> return UnlockResult.CorruptedVault
                is EnvelopeResult.Ok -> r.envelope
            }
            if (!SecurityPolicy.validateIterations(env.iterPin)) return UnlockResult.CorruptedVault

            val kPin: SecretKey = if (env.version >= 4) {
                if (!keystore.hasPepperKey()) return UnlockResult.NoPepper
                derivePepperedPinKey(pin, env.saltPin.base64(), env.iterPin)
            } else return UnlockResult.LegacyVaultNoPepper

            if (lockGuard.withLock { generation != startGen }) return UnlockResult.Aborted

            val master = Crypto.decrypt(kPin, env.wrappedKeyPin.base64(), aadFor(env))
            val masterKey = SecretKeySpec(master, "AES")

            val loaded0 = try {
                decodeEntries(masterKey, env)
            } catch (t: Throwable) {
                master.fill(0)
                return UnlockResult.CorruptedVault
            }

            val loaded = migrateEntriesIfNeeded(loaded0, masterKey, env)
            val published = publishUnlocked(startGen, master, loaded)
            master.fill(0)  // ✅ master zerado após instalar
            return if (published) UnlockResult.Success else UnlockResult.Aborted
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
        val startGen = captureGeneration()
        try {
            val env = when (val r = readEnvelope()) {
                is EnvelopeResult.Missing -> return UnlockResult.NoVault
                is EnvelopeResult.Corrupt -> return UnlockResult.CorruptedVault
                is EnvelopeResult.Ok -> r.envelope
            }
            if (!SecurityPolicy.validateIterations(env.iterPhrase)) return UnlockResult.CorruptedVault

            val normalized = SecurityPolicy.normalizePassphrase(phrase) // 1 String transitória
            phrase.fill('\u0000')

            val phraseChars = normalized.toCharArray()
            val kPh: SecretKey = try {
                Crypto.derive(phraseChars, env.saltPhrase.base64(), env.iterPhrase)
            } finally {
                phraseChars.fill('\u0000')
            }

            if (lockGuard.withLock { generation != startGen }) return UnlockResult.Aborted

            val master = Crypto.decrypt(kPh, env.wrappedKeyPhrase.base64(), aadFor(env))
            val masterKey = SecretKeySpec(master, "AES")

            val loaded0 = try {
                decodeEntries(masterKey, env)
            } catch (t: Throwable) {
                master.fill(0)
                return UnlockResult.CorruptedVault
            }

            val loaded = migrateEntriesIfNeeded(loaded0, masterKey, env)
            val published = publishUnlocked(startGen, master, loaded)
            master.fill(0)  // ✅ master zerado após instalar
            return if (published) UnlockResult.Success else UnlockResult.Aborted
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
    // Biometria
    // ------------------------------------------------------------------
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

            if (lockGuard.withLock { generation != startGen }) return UnlockResult.Aborted

            val aad = aadFor(env)
            cipher.updateAAD(aad)
            val master = cipher.doFinal(wrapped, 12, wrapped.size - 12)
            val masterKey = SecretKeySpec(master, "AES")

            val loaded0 = try {
                decodeEntries(masterKey, env)
            } catch (t: Throwable) {
                master.fill(0)
                return UnlockResult.CorruptedVault
            }

            val loaded = migrateEntriesIfNeeded(loaded0, masterKey, env)
            val published = publishUnlocked(startGen, master, loaded)
            master.fill(0)  // ✅ master zerado após instalar
            if (published) UnlockResult.Success else UnlockResult.Aborted
        } catch (e: GeneralSecurityException) {
            UnlockResult.WrongCredential
        } catch (e: Exception) {
            UnlockResult.Failure(e)
        }
    }

    fun enrollBiometric(cipher: Cipher): UnlockResult {
        val master = lockGuard.withLock { keyBytes?.copyOf() }
            ?: return UnlockResult.Failure(IllegalStateException("Cofre trancado"))
        try {
            val env = when (val r = readEnvelope()) {
                is EnvelopeResult.Missing -> return UnlockResult.NoVault
                is EnvelopeResult.Corrupt -> return UnlockResult.CorruptedVault
                is EnvelopeResult.Ok -> r.envelope
            }
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

    fun hasBiometricEnrollment(): Boolean {
        val r = readEnvelope()
        return r is EnvelopeResult.Ok && r.envelope.wrappedKeyKeystore != null
    }

    fun getBiometricIv(): ByteArray? {
        val r = readEnvelope() as? EnvelopeResult.Ok ?: return null
        val wrapped = r.envelope.wrappedKeyKeystore
            ?.let { runCatching { it.base64() }.getOrNull() } ?: return null
        return if (wrapped.size >= 12) wrapped.copyOfRange(0, 12) else null
    }

    fun disableBiometric(): UnlockResult = try {
        val env = when (val r = readEnvelope()) {
            is EnvelopeResult.Missing -> return UnlockResult.NoVault
            is EnvelopeResult.Corrupt -> return UnlockResult.CorruptedVault
            is EnvelopeResult.Ok -> r.envelope
        }
        persistAtomicallyOrThrow(env.copy(wrappedKeyKeystore = null))
        UnlockResult.Success
    } catch (t: Throwable) {
        UnlockResult.Failure(t)
    }

    fun rewrapPinWithCurrentMaster(newPin: CharArray): UnlockResult {
        val (master, gen) = lockGuard.withLock {
            val b = keyBytes ?: return UnlockResult.Failure(IllegalStateException("Cofre trancado"))
            b.copyOf() to generation
        }
        try {
            if (!SecurityPolicy.isStrongPin(newPin)) return UnlockResult.WrongCredential
            keystore.createPepperKey()
            val env = when (val r = readEnvelope()) {
                is EnvelopeResult.Missing -> return UnlockResult.NoVault
                is EnvelopeResult.Corrupt -> return UnlockResult.CorruptedVault
                is EnvelopeResult.Ok -> r.envelope
            }
            val newSaltPin = Crypto.randomBytes(SecurityPolicy.SALT_LENGTH_BYTES)
            val newHeader = env.copy(saltPin = newSaltPin.toBase64(), version = 4)
            val aad = aadFor(newHeader)

            val kPin = derivePepperedPinKey(newPin, newSaltPin, newHeader.iterPin)
            val wrappedPin = Crypto.encrypt(kPin, master, aad)

            val masterKey = SecretKeySpec(master, "AES")
            val dataPlain = Crypto.decrypt(masterKey, env.data.base64(), aadFor(env))
            val dataCipher = Crypto.encrypt(masterKey, dataPlain, aad)

            if (lockGuard.withLock { generation != gen }) return UnlockResult.Aborted

            persistAtomicallyOrThrow(
                newHeader.copy(wrappedKeyPin = wrappedPin.toBase64(), data = dataCipher.toBase64())
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
    // Acesso às entradas — UI recebe apenas EntryItem (sem pass)
    // ------------------------------------------------------------------
    fun getEntrySummaries(): List<EntryItem> = lockGuard.withLock {
        entries.map { EntryItem(it.id, it.name, it.user) }
    }

    /**
     * Leitura sob demanda para copiar/editar. Retorna o `String` já
     * existente dentro de [entries] — sem cópia adicional. Não expor
     * no `StateFlow` da UI; usar apenas pontualmente.
     */
    fun getEntryPasswordSnapshot(id: String): String? = lockGuard.withLock {
        entries.firstOrNull { it.id == id }?.pass
    }

    /** Mantido para testes; a UI não deve usar. */
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
    // ==================================================================
    // Troca de credenciais e upgrade de iterações
    // ==================================================================

    /**
     * Indica se o vault atual pode ser promovido para a política atual
     * de iterações. Não faz nada — apenas consulta.
     */
    fun needsIterationUpgrade(): Boolean {
        val r = readEnvelope() as? EnvelopeResult.Ok ?: return false
        if (r.envelope.version < 4) return false // v3 não tem pepper
        return r.envelope.iterPin < SecurityPolicy.PBKDF2_ITERATIONS ||
                r.envelope.iterPhrase < SecurityPolicy.PBKDF2_ITERATIONS
    }

    /**
     * Troca o PIN mantendo o salt e a iteração atuais.
     *
     * Pré-condições:
     *  - Cofre destrancado.
     *  - `currentPin` confere com o `wrappedKeyPin` atual.
     *  - `newPin` atende à política de PIN forte.
     *
     * Consequência: apenas `wrappedKeyPin` é re-embrulhado. Frase e
     * biometria continuam funcionando (o AAD não muda).
     */
    fun changePin(currentPin: CharArray, newPin: CharArray): UnlockResult {
        return try {
            val master = lockGuard.withLock { keyBytes?.copyOf() }
                ?: return UnlockResult.Failure(IllegalStateException("Cofre trancado"))

            try {
                if (!SecurityPolicy.isStrongPin(newPin)) return UnlockResult.WrongCredential

                val env = when (val r = readEnvelope()) {
                    is EnvelopeResult.Missing -> return UnlockResult.NoVault
                    is EnvelopeResult.Corrupt -> return UnlockResult.CorruptedVault
                    is EnvelopeResult.Ok -> r.envelope
                }
                if (env.version < 4) return UnlockResult.LegacyVaultNoPepper

                // 1) Verificar PIN atual
                val kCurrent = try {
                    if (!keystore.hasPepperKey()) return UnlockResult.NoPepper
                    derivePepperedPinKey(currentPin, env.saltPin.base64(), env.iterPin)
                } catch (e: IllegalStateException) {
                    return UnlockResult.NoPepper
                }
                try {
                    val test = Crypto.decrypt(kCurrent, env.wrappedKeyPin.base64(), aadFor(env))
                    val ok = test.contentEquals(master)
                    test.fill(0)
                    if (!ok) return UnlockResult.WrongCredential
                } catch (e: GeneralSecurityException) {
                    return UnlockResult.WrongCredential
                }

                // 2) Re-embrulhar com o novo PIN, MESMO salt e iteração
                val kNew = derivePepperedPinKey(newPin, env.saltPin.base64(), env.iterPin)
                val newWrapped = Crypto.encrypt(kNew, master, aadFor(env))

                // 3) Persistir
                persistAtomicallyOrThrow(env.copy(wrappedKeyPin = newWrapped.toBase64()))
                UnlockResult.Success
            } finally {
                master.fill(0)
                currentPin.fill('\u0000')
                newPin.fill('\u0000')
            }
        } catch (t: Throwable) {
            UnlockResult.Failure(t)
        }
    }

    /**
     * Troca a frase mantendo o salt e a iteração atuais.
     * Mesma lógica de [changePin], mas re-embrulha só `wrappedKeyPhrase`.
     */
    fun changePassphrase(
        currentPhrase: CharArray,
        newPhrase: CharArray
    ): UnlockResult {
        return try {
            val master = lockGuard.withLock { keyBytes?.copyOf() }
                ?: return UnlockResult.Failure(IllegalStateException("Cofre trancado"))

            try {
                val normalizedNew = SecurityPolicy.normalizePassphrase(newPhrase)
                newPhrase.fill('\u0000')

                if (!SecurityPolicy.isStrongPassphrase(normalizedNew)) {
                    return UnlockResult.WrongCredential
                }

                val env = when (val r = readEnvelope()) {
                    is EnvelopeResult.Missing -> return UnlockResult.NoVault
                    is EnvelopeResult.Corrupt -> return UnlockResult.CorruptedVault
                    is EnvelopeResult.Ok -> r.envelope
                }

                // 1) Verificar frase atual
                val normalizedCurrent = SecurityPolicy.normalizePassphrase(currentPhrase)
                currentPhrase.fill('\u0000')

                val currentChars = normalizedCurrent.toCharArray()
                val kCurrent: SecretKey = try {
                    Crypto.derive(currentChars, env.saltPhrase.base64(), env.iterPhrase)
                } finally {
                    currentChars.fill('\u0000')
                }
                try {
                    val test = Crypto.decrypt(kCurrent, env.wrappedKeyPhrase.base64(), aadFor(env))
                    val ok = test.contentEquals(master)
                    test.fill(0)
                    if (!ok) return UnlockResult.WrongCredential
                } catch (e: GeneralSecurityException) {
                    return UnlockResult.WrongCredential
                }

                // 2) Re-embrulhar com a nova frase, MESMO salt e iteração
                val newChars = normalizedNew.toCharArray()
                val kNew: SecretKey = try {
                    Crypto.derive(newChars, env.saltPhrase.base64(), env.iterPhrase)
                } finally {
                    newChars.fill('\u0000')
                }
                val newWrapped = Crypto.encrypt(kNew, master, aadFor(env))

                // 3) Persistir
                persistAtomicallyOrThrow(
                    env.copy(wrappedKeyPhrase = newWrapped.toBase64())
                )
                UnlockResult.Success
            } finally {
                master.fill(0)
            }
        } catch (t: Throwable) {
            UnlockResult.Failure(t)
        }
    }

    /**
     * Promove o vault para as iterações atuais do PBKDF2.
     *
     * Como o AAD inclui `iterPin`, `iterPhrase`, `saltPin` e `saltPhrase`,
     * re-embrulhar os wrappers com novos salt/iteração invalida **todos**
     * os campos cifrados. Por isso esta operação:
     *
     *  - Exige o cofre destrancado.
     *  - Exige **ambas** as credenciais (para re-embrulhar cada wrapper).
     *  - Gera novos salts.
     *  - **Invalida a biometria** (o usuário precisa re-cadastrar).
     *
     * Retorna [UnlockResult.Success] em caso de sucesso. Não chame
     * se [needsIterationUpgrade] for falso (no-op ou erro).
     */
    fun upgradeIterations(
        currentPin: CharArray,
        currentPhrase: CharArray
    ): UnlockResult {
        return try {
            val master = lockGuard.withLock { keyBytes?.copyOf() }
                ?: return UnlockResult.Failure(IllegalStateException("Cofre trancado"))

            try {
                val env = when (val r = readEnvelope()) {
                    is EnvelopeResult.Missing -> return UnlockResult.NoVault
                    is EnvelopeResult.Corrupt -> return UnlockResult.CorruptedVault
                    is EnvelopeResult.Ok -> r.envelope
                }
                if (env.version < 4) return UnlockResult.LegacyVaultNoPepper

                // 1) Verificar PIN atual
                val kCurrentPin = try {
                    if (!keystore.hasPepperKey()) return UnlockResult.NoPepper
                    derivePepperedPinKey(currentPin, env.saltPin.base64(), env.iterPin)
                } catch (e: IllegalStateException) {
                    return UnlockResult.NoPepper
                }
                try {
                    val test = Crypto.decrypt(kCurrentPin, env.wrappedKeyPin.base64(), aadFor(env))
                    val ok = test.contentEquals(master)
                    test.fill(0)
                    if (!ok) return UnlockResult.WrongCredential
                } catch (e: GeneralSecurityException) {
                    return UnlockResult.WrongCredential
                }

                // 2) Verificar frase atual
                val normalizedPhrase = SecurityPolicy.normalizePassphrase(currentPhrase)
                currentPhrase.fill('\u0000')

                val phraseChars = normalizedPhrase.toCharArray()
                val kCurrentPhrase: SecretKey = try {
                    Crypto.derive(phraseChars, env.saltPhrase.base64(), env.iterPhrase)
                } finally {
                    phraseChars.fill('\u0000')
                }
                try {
                    val test = Crypto.decrypt(kCurrentPhrase, env.wrappedKeyPhrase.base64(), aadFor(env))
                    val ok = test.contentEquals(master)
                    test.fill(0)
                    if (!ok) return UnlockResult.WrongCredential
                } catch (e: GeneralSecurityException) {
                    return UnlockResult.WrongCredential
                }

                // 3) Decifrar entradas com o AAD atual
                val dataPlain = Crypto.decrypt(key(), env.data.base64(), aadFor(env))

                // 4) Novo header com salt/iter atualizados
                val newSaltPin = Crypto.randomBytes(SecurityPolicy.SALT_LENGTH_BYTES)
                val newSaltPhrase = Crypto.randomBytes(SecurityPolicy.SALT_LENGTH_BYTES)
                val newHeader = env.copy(
                    iterPin = SecurityPolicy.PBKDF2_ITERATIONS,
                    iterPhrase = SecurityPolicy.PBKDF2_ITERATIONS,
                    saltPin = newSaltPin.toBase64(),
                    saltPhrase = newSaltPhrase.toBase64(),
                    wrappedKeyKeystore = null, // AAD mudou → biometria inválida
                    data = ""
                )
                val newAad = aadFor(newHeader)

                // 5) Re-embrulhar tudo
                val newKPin = derivePepperedPinKey(currentPin, newSaltPin, newHeader.iterPin)

                val newPhraseChars = normalizedPhrase.toCharArray()
                val newKPhrase: SecretKey = try {
                    Crypto.derive(newPhraseChars, newSaltPhrase, newHeader.iterPhrase)
                } finally {
                    newPhraseChars.fill('\u0000')
                }

                val newWrappedPin = Crypto.encrypt(newKPin, master, newAad)
                val newWrappedPhrase = Crypto.encrypt(newKPhrase, master, newAad)
                val newData = Crypto.encrypt(key(), dataPlain, newAad)
                dataPlain.fill(0)

                // 6) Persistir
                persistAtomicallyOrThrow(
                    newHeader.copy(
                        wrappedKeyPin = newWrappedPin.toBase64(),
                        wrappedKeyPhrase = newWrappedPhrase.toBase64(),
                        data = newData.toBase64()
                    )
                )
                UnlockResult.Success
            } finally {
                master.fill(0)
                currentPin.fill('\u0000')
                currentPhrase.fill('\u0000')
            }
        } catch (t: Throwable) {
            UnlockResult.Failure(t)
        }
    }

    // ------------------------------------------------------------------
    // Persistência
    // ------------------------------------------------------------------
    private fun persistEntriesOrThrow(newList: List<VaultEntry>) {
        val env = when (val r = readEnvelope()) {
            is EnvelopeResult.Ok -> r.envelope
            is EnvelopeResult.Missing ->
                throw IOException("Envelope do cofre não encontrado: ${vaultFile.absolutePath}")
            is EnvelopeResult.Corrupt ->
                throw IOException("Envelope do cofre ilegível (${r.source})", r.cause)
        }
        val body = json.encodeToString(ListSerializer(VaultEntry.serializer()), newList)
        val cipher = Crypto.encrypt(key(), body.toByteArray(), aadFor(env))
        persistAtomicallyOrThrow(env.copy(data = cipher.toBase64()))
    }

    private fun persistAtomicallyOrThrow(env: VaultEnvelope) {
        val parent = vaultFile.parentFile
            ?: throw IOException("Diretório do cofre inválido: ${vaultFile.absolutePath}")
        val tmp = File(parent, "${vaultFile.name}.tmp")
        val bak = File(parent, "${vaultFile.name}.bak")

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

        if (vaultFile.exists()) {
            try {
                vaultFile.copyTo(bak, overwrite = true)
            } catch (e: Exception) {
                runCatching { tmp.delete() }
                throw IOException("Falha ao criar backup: ${bak.absolutePath}", e)
            }
        }

        if (!tmp.renameTo(vaultFile)) {
            try {
                tmp.copyTo(vaultFile, overwrite = true)
                tmp.delete()
            } catch (e: Exception) {
                runCatching { tmp.delete() }
                throw IOException("Falha ao substituir vault.json: ${vaultFile.absolutePath}", e)
            }
        }

        if (!vaultFile.exists()) {
            throw IOException("vault.json não existe após gravação: ${vaultFile.absolutePath}")
        }
        _exists.value = true
    }

    private fun aadFor(env: VaultEnvelope): ByteArray =
        "v=${env.version}|ip=${env.iterPin}|iph=${env.iterPhrase}|sp=${env.saltPin}|sph=${env.saltPhrase}"
            .toByteArray(Charsets.UTF_8)

    companion object {
        private const val MIN_SUPPORTED_VERSION = 3
        private const val MAX_SUPPORTED_VERSION = 4
    }
}
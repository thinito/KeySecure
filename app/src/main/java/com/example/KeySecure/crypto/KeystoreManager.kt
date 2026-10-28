package com.example.KeySecure.crypto

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.security.keystore.UserNotAuthenticatedException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

/**
 * Nível de segurança da chave de pepper, do mais forte para o mais fraco.
 * `SECURITY_LEVEL_UNKNOWN` é tratado como software (pior caso).
 */
enum class PepperSecurityLevel {
    STRONGBOX,          // HSM dedicado (Titan M, etc.)
    TRUSTED_ENVIRONMENT, // TEE (ARM TrustZone)
    SOFTWARE,           // Keystore em software — chave extraível com root
    UNKNOWN             // Não foi possível determinar — trate como software
}

/**
 * Android Keystore com duas chaves:
 *  - BIOMETRIC_ALIAS: AES-256-GCM, exige autenticação.
 *  - PEPPER_ALIAS:    HMAC-SHA256, sem autenticação, mas com:
 *      • `setUnlockedDeviceRequired(true)` quando API 28+
 *      • tentativa de StrongBox com fallback para TEE/software
 *      • verificação de `securityLevel` para detectar software
 *
 * ⚠️ Em dispositivos com Keystore **software** (sem TEE/StrongBox), a chave
 * HMAC é extraível com root, e o pepper não oferece proteção real contra
 * brute force offline. O app deve avisar o usuário nesse caso (ver
 * `getPepperSecurityLevel()`).
 */
class KeystoreManager : IKeystore {

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val BIOMETRIC_ALIAS = "keysecure_master_wrapper_v1"
        private const val PEPPER_ALIAS = "keysecure_pin_pepper_v1"
        private const val TAG_BITS = 128
    }

    private val keyStore: KeyStore by lazy {
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    }

    // ------------------------------------------------------------------
    // Chave biométrica (inalterada)
    // ------------------------------------------------------------------
    override fun hasKey(): Boolean = keyStore.containsAlias(BIOMETRIC_ALIAS)

    override fun createKey() {
        if (hasKey()) return
        val builder = KeyGenParameterSpec.Builder(
            BIOMETRIC_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            builder.setInvalidatedByBiometricEnrollment(true)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setUserAuthenticationParameters(
                0,
                KeyProperties.AUTH_BIOMETRIC_STRONG
            )
        }

        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
            .apply { init(builder.build()) }
            .generateKey()
    }

    override fun getKey(): SecretKey {
        val entry = keyStore.getEntry(BIOMETRIC_ALIAS, null) as KeyStore.SecretKeyEntry
        return entry.secretKey
    }

    override fun deleteKey() {
        if (hasKey()) keyStore.deleteEntry(BIOMETRIC_ALIAS)
    }

    // ------------------------------------------------------------------
    // Pepper HMAC — com endurecimento por hardware
    // ------------------------------------------------------------------
    override fun hasPepperKey(): Boolean = keyStore.containsAlias(PEPPER_ALIAS)

    /**
     * Cria a chave de pepper com o **melhor nível de segurança disponível**,
     * em ordem decrescente:
     *
     *  1. StrongBox + unlockedDeviceRequired (API 28+)
     *  2. TEE + unlockedDeviceRequired (API 28+)
     *  3. TEE sem unlockedDeviceRequired (dispositivo sem lock screen seguro)
     *  4. Software (último recurso — emite aviso via [getPepperSecurityLevel])
     *
     * Cada fallback é silencioso do ponto de vista do chamador; o nível
     * resultante pode ser consultado depois com [getPepperSecurityLevel].
     */
    override fun createPepperKey() {
        if (hasPepperKey()) return

        // Ordem de tentativas: StrongBox → TEE/unlocked → TEE → software.
        val attempts: List<Pair<Boolean, Boolean>> = buildList {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                add(true to true)   // StrongBox + unlockedDeviceRequired
                add(false to true)  // TEE + unlockedDeviceRequired
            }
            add(false to false)     // TEE ou software, sem restrição de unlock
        }

        var lastError: Throwable? = null
        for ((strongBox, unlockedRequired) in attempts) {
            try {
                generatePepperKey(strongBox, unlockedRequired)
                return
            } catch (e: StrongBoxUnavailableException) {
                lastError = e
                // StrongBox indisponível ou algoritmo não suportado → tenta próximo
            } catch (e: UserNotAuthenticatedException) {
                lastError = e
                // Dispositivo sem lock screen seguro → tenta sem unlockedDeviceRequired
            } catch (e: Exception) {
                lastError = e
                // Outras falhas (ex.: InvalidAlgorithmParameterException) → tenta próximo
            }
        }

        throw IllegalStateException(
            "Não foi possível criar a chave de pepper com nenhum nível de segurança.",
            lastError
        )
    }

    private fun generatePepperKey(strongBox: Boolean, unlockedRequired: Boolean) {
        val builder = KeyGenParameterSpec.Builder(
            PEPPER_ALIAS,
            KeyProperties.PURPOSE_SIGN
        )
            .setKeySize(256)
            .setDigests(KeyProperties.DIGEST_SHA256)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setIsStrongBoxBacked(strongBox)
            builder.setUnlockedDeviceRequired(unlockedRequired)
        }

        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, ANDROID_KEYSTORE)
            .apply { init(builder.build()) }
            .generateKey()
    }

    override fun computePepperHmac(data: ByteArray): ByteArray {
        val key = keyStore.getKey(PEPPER_ALIAS, null) as? SecretKey
            ?: throw IllegalStateException("Pepper key não encontrada")
        val mac = Mac.getInstance("HmacSHA256", ANDROID_KEYSTORE)
        mac.init(key)
        return mac.doFinal(data)
    }

    override fun deletePepperKey() {
        if (hasPepperKey()) keyStore.deleteEntry(PEPPER_ALIAS)
    }

    // ------------------------------------------------------------------
    // Detecção do nível de segurança da chave de pepper
    // ------------------------------------------------------------------
    /**
     * Retorna o nível de segurança da chave de pepper.
     *
     * - API 31+: usa `KeyInfo.securityLevel`.
     * - API 28–30: usa `KeyInfo.isInsideSecureHardware()` (true = TEE/StrongBox,
     *   false = software). StrongBox não é distinguível de TEE nessa faixa.
     * - API 26–27: não há como inspecionar; assume [PepperSecurityLevel.UNKNOWN].
     *
     * Retorna `null` se a chave não existir.
     */
    override fun getPepperSecurityLevel(): PepperSecurityLevel? {
        if (!hasPepperKey()) return null

        val key = keyStore.getKey(PEPPER_ALIAS, null) as? SecretKey ?: return null
        val factory = SecretKeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE)

        return try {
            val keyInfo = factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
            when {
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
                    when (keyInfo.securityLevel) {
                        KeyProperties.SECURITY_LEVEL_STRONGBOX -> PepperSecurityLevel.STRONGBOX
                        KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT ->
                            PepperSecurityLevel.TRUSTED_ENVIRONMENT
                        KeyProperties.SECURITY_LEVEL_SOFTWARE -> PepperSecurityLevel.SOFTWARE
                        else -> PepperSecurityLevel.UNKNOWN
                    }
                }
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.P -> {
                    if (keyInfo.isInsideSecureHardware) {
                        PepperSecurityLevel.TRUSTED_ENVIRONMENT // ou StrongBox, indistinguível
                    } else {
                        PepperSecurityLevel.SOFTWARE
                    }
                }
                else -> PepperSecurityLevel.UNKNOWN
            }
        } catch (t: Throwable) {
            PepperSecurityLevel.UNKNOWN
        }
    }

    /**
     * `true` se a chave de pepper está em hardware (StrongBox ou TEE).
     * Em software ou desconhecido, retorna `false` (trata como inseguro).
     */
    fun isPepperHardwareBacked(): Boolean = when (getPepperSecurityLevel()) {
        PepperSecurityLevel.STRONGBOX,
        PepperSecurityLevel.TRUSTED_ENVIRONMENT -> true
        else -> false
    }

    // ------------------------------------------------------------------
    // Cipher helpers (biometria)
    // ------------------------------------------------------------------
    fun getEncryptCipher(): Cipher {
        val key = getKey()
        return Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.ENCRYPT_MODE, key)
        }
    }

    fun getDecryptCipher(iv: ByteArray): Cipher {
        val key = getKey()
        return Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, iv))
        }
    }
}
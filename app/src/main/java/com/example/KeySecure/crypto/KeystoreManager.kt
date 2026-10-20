package com.example.KeySecure.crypto

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Android Keystore com duas chaves:
 *  - BIOMETRIC_ALIAS: AES-256-GCM, exige autenticação, envolve a master.
 *  - PEPPER_ALIAS:    HMAC-SHA256, sem autenticação, pimenta o PIN.
 *
 * O pepper é o coração da defesa contra força bruta offline:
 * sem a chave HMAC (que nunca sai do TEE/StrongBox), o PBKDF2 do PIN
 * não pode ser testado fora do aparelho.
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
    // Chave biométrica
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
    // Pepper HMAC
    // ------------------------------------------------------------------
    override fun hasPepperKey(): Boolean = keyStore.containsAlias(PEPPER_ALIAS)

    override fun createPepperKey() {
        if (hasPepperKey()) return
        val spec = KeyGenParameterSpec.Builder(
            PEPPER_ALIAS,
            KeyProperties.PURPOSE_SIGN
        )
            .setKeySize(256)
            .setDigests(KeyProperties.DIGEST_SHA256)
            // SEM setUserAuthenticationRequired(true): queremos que o HMAC
            // possa ser computado sem prompt, no momento do desbloqueio por PIN.
            .build()

        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, ANDROID_KEYSTORE)
            .apply { init(spec) }
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
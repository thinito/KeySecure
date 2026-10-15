package com.example.KeySecure.crypto

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/**
 * Gerencia a chave AES-256 armazenada no Android Keystore (TEE/StrongBox),
 * exigindo autenticação do usuário (biometria ou credencial do dispositivo).
 *
 * embrulha a master key com essa chave de hardware.
 * a autenticação é feita via BiometricPrompt com CryptoObject.
 */
class KeystoreManager {

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val ALIAS = "keysecure_master_wrapper_v1"
    }

    private val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    fun hasKey(): Boolean = keyStore.containsAlias(ALIAS)

    fun createKey() {
        if (hasKey()) return
        val builder = KeyGenParameterSpec.Builder(
            ALIAS,
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
                0, // sem timeout: exige auth a cada uso
                KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
            )
        }

        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
            .apply { init(builder.build()) }
            .generateKey()
    }

    fun getKey(): SecretKey {
        val entry = keyStore.getEntry(ALIAS, null) as KeyStore.SecretKeyEntry
        return entry.secretKey
    }

    fun deleteKey() {
        if (hasKey()) keyStore.deleteEntry(ALIAS)
    }
}
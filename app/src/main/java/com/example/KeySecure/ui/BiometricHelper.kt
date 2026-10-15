package com.example.KeySecure.ui

import android.content.Context
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.example.KeySecure.crypto.KeystoreManager
import javax.crypto.Cipher

/**
 * autenticação biométrica usando androidx.biometric
 * com CryptoObject vinculado à chave do Android Keystore
 */
object BiometricHelper {

    fun isAvailable(context: Context): Boolean {
        val manager = BiometricManager.from(context)
        val authenticators = BiometricManager.Authenticators.BIOMETRIC_STRONG or
                BiometricManager.Authenticators.DEVICE_CREDENTIAL
        return manager.canAuthenticate(authenticators) == BiometricManager.BIOMETRIC_SUCCESS
    }

    fun prompt(
        activity: FragmentActivity,
        keystore: KeystoreManager,
        onSuccess: (Cipher, ByteArray) -> Unit,
        onError: (String) -> Unit
    ) {
        val key = keystore.getKey()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key)

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Desbloquear cofre")
            .setSubtitle("Use biometria ou credencial")
            .setAllowedAuthenticators(
                BiometricManager.Authenticators.BIOMETRIC_STRONG or
                        BiometricManager.Authenticators.DEVICE_CREDENTIAL
            )
            .build()

        val prompt = BiometricPrompt(
            activity,
            ContextCompat.getMainExecutor(activity),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val c = result.cryptoObject?.cipher
                    if (c != null) onSuccess(c, c.iv) else onError("Cipher indisponível")
                }
                override fun onAuthenticationError(code: Int, msg: CharSequence) {
                    onError(msg.toString())
                }
            }
        )
        prompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
    }
}
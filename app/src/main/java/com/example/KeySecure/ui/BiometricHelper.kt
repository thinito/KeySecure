package com.example.KeySecure.ui

import android.content.Context
import android.security.keystore.KeyPermanentlyInvalidatedException
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.example.KeySecure.crypto.KeystoreManager
import javax.crypto.Cipher

/**
 * Fluxo biométrico usando APENAS BIOMETRIC_STRONG com CryptoObject.
 * DEVICE_CREDENTIAL + CryptoObject só funciona a partir da API 30.
 */
object BiometricHelper {

    fun isAvailable(context: Context): Boolean {
        val manager = BiometricManager.from(context)
        return manager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
                BiometricManager.BIOMETRIC_SUCCESS
    }

    /** Enrollment: gera chave (se preciso) e pede autenticação com Cipher ENCRYPT. */
    fun promptForEnroll(
        activity: FragmentActivity,
        keystore: KeystoreManager,
        onSuccess: (Cipher) -> Unit,
        onError: (String) -> Unit
    ) {
        try {
            keystore.createKey()
        } catch (e: Exception) {
            onError("Falha ao criar chave: ${e.message ?: e.javaClass.simpleName}")
            return
        }

        val cipher = try {
            keystore.getEncryptCipher()
        } catch (e: Exception) {
            onError("Falha ao preparar criptografia: ${e.message ?: e.javaClass.simpleName}")
            return
        }
        showPrompt(activity, cipher, "Ativar biometria", onSuccess, onError)
    }

    /**
     * Unlock: inicializa Cipher DECRYPT com o IV do blob e pede autenticação.
     * Se a chave foi permanentemente invalidada, apaga e sinaliza.
     */
    fun promptForUnlock(
        activity: FragmentActivity,
        keystore: KeystoreManager,
        iv: ByteArray,
        onSuccess: (Cipher) -> Unit,
        onInvalidated: () -> Unit,
        onError: (String) -> Unit
    ) {
        val cipher = try {
            keystore.getDecryptCipher(iv)
        } catch (e: KeyPermanentlyInvalidatedException) {
            runCatching { keystore.deleteKey() }
            onInvalidated()
            return
        } catch (e: Exception) {
            onError("Falha ao preparar criptografia: ${e.message ?: e.javaClass.simpleName}")
            return
        }
        showPrompt(activity, cipher, "Desbloquear cofre", onSuccess, onError)
    }

    private fun showPrompt(
        activity: FragmentActivity,
        cipher: Cipher,
        title: String,
        onSuccess: (Cipher) -> Unit,
        onError: (String) -> Unit
    ) {
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .setNegativeButtonText("Cancelar")
            .build()

        val prompt = BiometricPrompt(
            activity,
            ContextCompat.getMainExecutor(activity),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val c = result.cryptoObject?.cipher
                    if (c != null) onSuccess(c) else onError("Cipher indisponível após autenticação")
                }
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    onError(errString.toString())
                }
            }
        )
        prompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
    }
}
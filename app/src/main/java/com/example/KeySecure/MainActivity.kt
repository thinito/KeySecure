package com.example.KeySecure

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.example.KeySecure.data.SecurityPolicy
import com.example.KeySecure.data.VaultEntry
import com.example.KeySecure.ui.*
import com.example.KeySecure.R
import androidx.lifecycle.ViewModelProvider

class MainActivity : AppCompatActivity () {

    private val unlockVm: UnlockViewModel by lazy { 
        ViewModelProvider(this)[UnlockViewModel::class.java] 
    }
    private val vaultVm: VaultViewModel by lazy { 
        ViewModelProvider(this)[VaultViewModel::class.java] 
    }
    private val setupVm: SetupViewModel by lazy { 
        ViewModelProvider(this)[SetupViewModel::class.java] 
    }

    private val keyApp: KeySecureApp get() = application as KeySecureApp

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    RootScreen(unlockVm, vaultVm, setupVm, keyApp)
                }
            }
        }
    }

    override fun onStop() {
        super.onStop()
        // NÃO limpa o clipboard aqui.
        // Lock após timeout configurável (ver LockTimeoutHandler).
        LockTimeoutHandler.scheduleLock(keyApp.vault)
    }

    override fun onStart() {
        super.onStart()
        LockTimeoutHandler.cancel()
    }
}

@Composable
private fun RootScreen(
    unlockVm: UnlockViewModel,
    vaultVm: VaultViewModel,
    setupVm: SetupViewModel,
    keyApp: KeySecureApp
) {
    // Coleta o estado, mas o Vault já existe (criado no KeySecureApp)
    val unlocked by keyApp.vault.unlocked.collectAsStateWithLifecycle()

    // vaultExists é barato (File.exists), pode ficar aqui
    val vaultExists = remember { keyApp.vault.exists() }

    when {
        !vaultExists -> SetupScreen(setupVm)
        unlocked -> VaultScreen(vaultVm)
        else -> UnlockScreen(unlockVm)
    }
}
@Composable
private fun UnlockScreen(vm: UnlockViewModel) {
    val state by vm.state.collectAsStateWithLifecycle()
    Column(
        Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.Center
    ) {
        Text(stringResource(R.string.unlock_title), style = MaterialTheme.typography.headlineMedium)
        Spacer(Modifier.height(16.dp))

        if (state.usePhrase) {
            OutlinedTextField(
                value = state.phrase,
                onValueChange = vm::onPhraseChange,
                label = { Text(stringResource(R.string.unlock_phrase_hint)) },
                visualTransformation = PasswordVisualTransformation(),
                singleLine = true,
                isError = state.error != null,
                enabled = !state.isLocked && !state.isProcessing
            )
        } else {
            OutlinedTextField(
                value = state.pin,
                onValueChange = vm::onPinChange,
                label = { Text(stringResource(R.string.unlock_pin_hint, SecurityPolicy.MIN_PIN_LENGTH)) },
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                    keyboardType = KeyboardType.NumberPassword
                ),
                singleLine = true,
                isError = state.error != null,
                enabled = !state.isLocked && !state.isProcessing
            )
        }

        state.error?.let {
            Spacer(Modifier.height(8.dp))
            Text(it, color = MaterialTheme.colorScheme.error)
        }
        if (state.isLocked) {
            Spacer(Modifier.height(8.dp))
            Text(stringResource(R.string.error_locked_out, state.lockoutRemainingSec))
        }

        Spacer(Modifier.height(16.dp))
        Button(
            onClick = vm::submit,
            enabled = !state.isLocked && !state.isProcessing
        ) { Text(stringResource(R.string.unlock_button)) }

        TextButton(onClick = vm::toggleUsePhrase, enabled = !state.isProcessing) {
            Text(if (state.usePhrase) "Usar PIN" else "Usar frase-chave")
        }
    }
}

@Composable
private fun SetupScreen(vm: SetupViewModel) {
    val state by vm.state.collectAsStateWithLifecycle()
    Column(
        Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.Center
    ) {
        Text(stringResource(R.string.setup_title), style = MaterialTheme.typography.headlineMedium)
        Spacer(Modifier.height(16.dp))
        OutlinedTextField(
            value = state.pin,
            onValueChange = vm::onPinChange,
            label = { Text(stringResource(R.string.setup_pin_hint)) },
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                keyboardType = KeyboardType.NumberPassword
            ),
            isError = state.error != null
        )
        Spacer(Modifier.height(8.dp))
        OutlinedTextField(
            value = state.phrase,
            onValueChange = vm::onPhraseChange,
            label = { Text(stringResource(R.string.setup_phrase_hint)) },
            visualTransformation = PasswordVisualTransformation(),
            isError = state.error != null
        )
        state.error?.let {
            Spacer(Modifier.height(8.dp))
            Text(it, color = MaterialTheme.colorScheme.error)
        }
        Spacer(Modifier.height(16.dp))
        Button(onClick = vm::create, enabled = !state.isProcessing) {
            Text(stringResource(R.string.setup_confirm))
        }
    }
}

@Composable
private fun VaultScreen(vm: VaultViewModel) {
    val context = LocalContext.current
    val entries by vm.entries.collectAsStateWithLifecycle()

    if (entries.isEmpty()) {
        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            Text(stringResource(R.string.vault_empty))
        }
        return
    }
    LazyColumn(Modifier.fillMaxSize().padding(16.dp)) {
        items(entries, key = { it.name + it.user }) { entry ->
            Row(
                Modifier.fillMaxWidth().padding(vertical = 8.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(Modifier.weight(1f)) {
                    Text(entry.name, style = MaterialTheme.typography.bodyLarge)
                    Text(entry.user, style = MaterialTheme.typography.bodySmall)
                }
                IconButton(onClick = { vm.copyPassword(context, entry.pass) }) {
                    Text(stringResource(R.string.vault_copy))
                }
                IconButton(onClick = { vm.delete(entry) }) {
                    Text(stringResource(R.string.vault_delete))
                }
            }
            Divider()
        }
    }
}
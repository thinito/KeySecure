package com.example.KeySecure

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.example.KeySecure.data.SecurityPolicy
import com.example.KeySecure.ui.UnlockViewModel
import com.example.KeySecure.ui.VaultViewModel
import com.example.KeySecure.util.ClipboardUtil

class MainActivity : ComponentActivity() {

    private val unlockVm: UnlockViewModel by viewModels()
    private val vaultVm: VaultViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Impede capturas de tela
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )
        setContent {
            MaterialTheme {
                Surface(Modifier.fillMaxSize()) {
                    RootScreen(unlockVm, vaultVm)
                }
            }
        }
    }

    override fun onStop() {
        super.onStop()
        vaultVm.lock()
        ClipboardUtil.clearNow(this)
    }
}

@Composable
private fun RootScreen(unlockVm: UnlockViewModel, vaultVm: VaultViewModel) {
    val state by unlockVm.state.collectAsStateWithLifecycle()

    if (state.unlocked) {
        VaultScreen(vaultVm)
    } else {
        UnlockScreen(unlockVm, state)
    }
}

@Composable
private fun UnlockScreen(
    vm: UnlockViewModel,
    state: com.example.KeySecure.ui.UnlockState
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        verticalArrangement = Arrangement.Center
    ) {
        Text(
            "Desbloquear Cofre",
            style = MaterialTheme.typography.headlineMedium
        )
        Spacer(Modifier.height(16.dp))

        OutlinedTextField(
            value = state.pin,
            onValueChange = vm::onPinChange,
            label = { Text("PIN (mín. ${SecurityPolicy.MIN_PIN_LENGTH} dígitos)") },
            visualTransformation = PasswordVisualTransformation(),
            singleLine = true,
            isError = state.error != null,
            enabled = !state.isLocked
        )

        state.error?.let {
            Spacer(Modifier.height(8.dp))
            Text(it, color = MaterialTheme.colorScheme.error)
        }

        Spacer(Modifier.height(16.dp))
        Button(
            onClick = vm::submit,
            enabled = !state.isLocked && SecurityPolicy.isValidPin(state.pin)
        ) { Text("Desbloquear") }
    }
}

@Composable
private fun VaultScreen(vm: VaultViewModel) {
    val context = LocalContext.current
    // Substitua por sua fonte real de dados
    val entries = remember { listOf<Pair<String, String>>() }

    LazyColumn(Modifier.fillMaxSize().padding(16.dp)) {
        items(entries.size) { i ->
            val (name, pass) = entries[i]
            Row(
                Modifier.fillMaxWidth().padding(vertical = 8.dp),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(name)
                IconButton(onClick = { vm.copyPassword(context, pass) }) {
                    Text("Copiar")
                }
            }
        }
    }
}
package com.example.KeySecure

import android.os.Bundle
import android.view.WindowManager
import android.widget.Toast
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.example.KeySecure.data.SecurityPolicy
import com.example.KeySecure.data.VaultEntry
import com.example.KeySecure.ui.*

class MainActivity : AppCompatActivity() {

    private val unlockVm: UnlockViewModel by viewModels()
    private val vaultVm: VaultViewModel by viewModels()
    private val setupVm: SetupViewModel by viewModels()

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

    override fun onStart() {
        super.onStart()
        LockTimeoutHandler.onActivityStarted(this, keyApp.vault)
    }

    override fun onStop() {
        super.onStop()
        LockTimeoutHandler.onActivityStopped(keyApp.vault)
    }

    override fun onDestroy() {
        super.onDestroy()
        if (isFinishing) {
            LockTimeoutHandler.onActivityDestroyed(keyApp.vault)
        }
    }
}

@Composable
private fun RootScreen(
    unlockVm: UnlockViewModel,
    vaultVm: VaultViewModel,
    setupVm: SetupViewModel,
    keyApp: KeySecureApp
) {
    val unlocked by keyApp.vault.unlocked.collectAsStateWithLifecycle()
    val vaultExists by keyApp.vault.exists.collectAsStateWithLifecycle()
    val setupState by setupVm.state.collectAsStateWithLifecycle()

    when {
        !vaultExists -> SetupScreen(setupVm, keyApp, setupState)
        setupState.pendingBiometricEnroll -> SetupScreen(setupVm, keyApp, setupState)
        unlocked -> VaultScreen(vaultVm)
        else -> UnlockScreen(unlockVm, keyApp)
    }
}

@Composable
private fun UnlockScreen(vm: UnlockViewModel, keyApp: KeySecureApp) {
    val state by vm.state.collectAsStateWithLifecycle()
    val context = LocalContext.current
    val activity = context as? FragmentActivity

    val hasBiometric = remember { keyApp.vault.hasBiometricEnrollment() }
    val biometricAvailable = remember { BiometricHelper.isAvailable(context) }
    val showBiometric = hasBiometric && biometricAvailable && activity != null

    Column(
        Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.Center
    ) {
        Text("Desbloquear Cofre", style = MaterialTheme.typography.headlineMedium)
        Spacer(Modifier.height(16.dp))

        if (state.usePhrase) {
            OutlinedTextField(
                value = state.phrase,
                onValueChange = vm::onPhraseChange,
                label = { Text("Frase-chave") },
                visualTransformation = PasswordVisualTransformation(),
                singleLine = true,
                isError = state.error != null,
                enabled = !state.isLocked && !state.isProcessing,
                modifier = Modifier.fillMaxWidth()
            )
        } else {
            OutlinedTextField(
                value = state.pin,
                onValueChange = vm::onPinChange,
                label = { Text("PIN (mín. ${SecurityPolicy.MIN_PIN_LENGTH} dígitos)") },
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                singleLine = true,
                isError = state.error != null,
                enabled = !state.isLocked && !state.isProcessing,
                modifier = Modifier.fillMaxWidth()
            )
        }

        state.error?.let {
            Spacer(Modifier.height(8.dp))
            Text(it, color = MaterialTheme.colorScheme.error)
        }
        if (state.isLocked) {
            Spacer(Modifier.height(8.dp))
            Text("Bloqueado. Tente em ${state.lockoutRemainingSec}s")
        }

        Spacer(Modifier.height(16.dp))
        Button(
            onClick = vm::submit,
            enabled = !state.isLocked && !state.isProcessing,
            modifier = Modifier.fillMaxWidth()
        ) { Text(if (state.isProcessing) "Verificando..." else "Desbloquear") }

        if (showBiometric) {
            Spacer(Modifier.height(8.dp))
            OutlinedButton(
                onClick = {
                    val iv = keyApp.vault.getBiometricIv()
                    if (iv == null) {
                        Toast.makeText(context, "Biometria indisponível", Toast.LENGTH_SHORT).show()
                        return@OutlinedButton
                    }
                    BiometricHelper.promptForUnlock(
                        activity = activity!!,
                        keystore = keyApp.keystore,
                        iv = iv,
                        onSuccess = { cipher ->
                            val result = keyApp.vault.unlockWithKeystoreCipher(cipher)
                            if (result !is UnlockResult.Success) {
                                Toast.makeText(context, "Falha: $result", Toast.LENGTH_LONG).show()
                            }
                        },
                        onInvalidated = {
                            keyApp.vault.disableBiometric()
                            Toast.makeText(
                                context,
                                "Biometria invalidada. Use o PIN e reative.",
                                Toast.LENGTH_LONG
                            ).show()
                        },
                        onError = { msg ->
                            Toast.makeText(context, "Biometria: $msg", Toast.LENGTH_LONG).show()
                        }
                    )
                },
                enabled = !state.isLocked && !state.isProcessing,
                modifier = Modifier.fillMaxWidth()
            ) { Text("Usar biometria") }
        }

        TextButton(
            onClick = vm::toggleUsePhrase,
            enabled = !state.isProcessing,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(if (state.usePhrase) "Usar PIN" else "Usar frase-chave")
        }
    }
}

@Composable
private fun SetupScreen(
    vm: SetupViewModel,
    keyApp: KeySecureApp,
    state: SetupState
) {
    val context = LocalContext.current
    val activity = context as? FragmentActivity

    LaunchedEffect(state.pendingBiometricEnroll) {
        if (state.pendingBiometricEnroll && activity != null) {
            BiometricHelper.promptForEnroll(
                activity = activity,
                keystore = keyApp.keystore,
                onSuccess = { cipher ->
                    val result = keyApp.vault.enrollBiometric(cipher)
                    if (result !is UnlockResult.Success) {
                        Toast.makeText(
                            context,
                            "Falha ao ativar biometria: $result",
                            Toast.LENGTH_LONG
                        ).show()
                    }
                    vm.finishBiometricEnroll()
                },
                onError = { msg ->
                    Toast.makeText(context, "Biometria: $msg", Toast.LENGTH_LONG).show()
                    vm.finishBiometricEnroll()
                }
            )
        }
    }

    Column(
        Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.Center
    ) {
        Text("Criar Cofre", style = MaterialTheme.typography.headlineMedium)
        Spacer(Modifier.height(16.dp))
        OutlinedTextField(
            value = state.pin,
            onValueChange = vm::onPinChange,
            label = { Text("PIN (6 a 12 dígitos)") },
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
            isError = state.error != null,
            enabled = !state.isProcessing && !state.done,
            modifier = Modifier.fillMaxWidth()
        )
        Spacer(Modifier.height(8.dp))
        OutlinedTextField(
            value = state.phrase,
            onValueChange = vm::onPhraseChange,
            label = { Text("Frase-chave (mín. 12 caracteres)") },
            visualTransformation = PasswordVisualTransformation(),
            isError = state.error != null,
            enabled = !state.isProcessing && !state.done,
            modifier = Modifier.fillMaxWidth()
        )
        state.error?.let {
            Spacer(Modifier.height(8.dp))
            Text(it, color = MaterialTheme.colorScheme.error)
        }
        Spacer(Modifier.height(16.dp))
        Button(
            onClick = vm::create,
            enabled = !state.isProcessing && !state.done,
            modifier = Modifier.fillMaxWidth()
        ) { Text(if (state.isProcessing) "Criando..." else "Criar") }
    }
}

// ---------------------------------------------------------------------------
// VaultScreen — Snackbar para erros + copy-and-swap respeitado na UI
// ---------------------------------------------------------------------------
@Composable
private fun VaultScreen(vm: VaultViewModel) {
    val context = LocalContext.current
    val entries by vm.entries.collectAsStateWithLifecycle()
    val lastError by vm.lastError.collectAsStateWithLifecycle()

    val snackbarHostState = remember { SnackbarHostState() }

    // Mostra qualquer erro de gravação propagado pelo VaultViewModel.
    LaunchedEffect(lastError) {
        lastError?.let { msg ->
            snackbarHostState.showSnackbar(msg)
            vm.clearError()
        }
    }

    var showDialog by remember { mutableStateOf(false) }
    var editingEntry by remember { mutableStateOf<VaultEntry?>(null) }
    var pendingDelete by remember { mutableStateOf<VaultEntry?>(null) }

    Scaffold(
        snackbarHost = { SnackbarHost(snackbarHostState) }
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            Row(
                Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text("Cofre", style = MaterialTheme.typography.headlineSmall, modifier = Modifier.weight(1f))
                Button(onClick = { editingEntry = null; showDialog = true }) { Text("Adicionar") }
                OutlinedButton(onClick = {
                    vm.lock()
                    Toast.makeText(context, "Cofre trancado", Toast.LENGTH_SHORT).show()
                }) { Text("Trancar") }
            }
            HorizontalDivider()

            if (entries.isEmpty()) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Text("Nenhuma entrada no cofre")
                        Spacer(Modifier.height(16.dp))
                        Button(onClick = { editingEntry = null; showDialog = true }) {
                            Text("Adicionar entrada")
                        }
                    }
                }
            } else {
                LazyColumn(Modifier.fillMaxSize(), contentPadding = PaddingValues(16.dp)) {
                    items(entries, key = { it.id }) { entry ->
                        Row(
                            Modifier.fillMaxWidth().padding(vertical = 8.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(Modifier.weight(1f)) {
                                Text(entry.name, style = MaterialTheme.typography.bodyLarge)
                                Text(entry.user, style = MaterialTheme.typography.bodySmall)
                            }
                            TextButton(onClick = {
                                vm.copyPassword(context, entry.pass)
                                Toast.makeText(context, "Senha copiada (30s)", Toast.LENGTH_SHORT).show()
                            }) { Text("Copiar") }
                            TextButton(onClick = { editingEntry = entry; showDialog = true }) { Text("Editar") }
                            TextButton(onClick = { pendingDelete = entry }) {
                                Text("Excluir", color = MaterialTheme.colorScheme.error)
                            }
                        }
                        HorizontalDivider()
                    }
                }
            }
        }
    }

    // Diálogo de adicionar/editar — só fecha se a gravação tiver sucesso.
    if (showDialog) {
        EntryDialog(
            initial = editingEntry,
            onDismiss = { showDialog = false; editingEntry = null },
            onSave = { name, user, pass ->
                val current = editingEntry
                val result: Result<Unit> = if (current == null) {
                    vm.add(name, user, pass).map { }
                } else {
                    vm.update(current.id, name, user, pass)
                }
                if (result.isSuccess) {
                    showDialog = false
                    editingEntry = null
                }
                result
            }
        )
    }

    // Confirmação de exclusão — só fecha se a gravação tiver sucesso.
    pendingDelete?.let { entry ->
        AlertDialog(
            onDismissRequest = { pendingDelete = null },
            title = { Text("Excluir entrada?") },
            text = { Text("A entrada '${entry.name}' será removida permanentemente.") },
            confirmButton = {
                TextButton(onClick = {
                    val result = vm.delete(entry.id)
                    if (result.isSuccess) {
                        pendingDelete = null
                    }
                    // Em caso de falha, `lastError` dispara o Snackbar e o
                    // diálogo permanece aberto para o usuário tentar de novo.
                }) {
                    Text("Excluir", color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = {
                TextButton(onClick = { pendingDelete = null }) { Text("Cancelar") }
            }
        )
    }
}

// ---------------------------------------------------------------------------
// EntryDialog — retorna (name, user, pass); o Vault gera o id
// ---------------------------------------------------------------------------
@Composable
private fun EntryDialog(
    initial: VaultEntry?,
    onDismiss: () -> Unit,
    onConfirm: (name: String, user: String, pass: String) -> Unit
) {
    // remember (NÃO rememberSaveable): segredos não vão para o Bundle.
    var name by remember { mutableStateOf(initial?.name ?: "") }
    var user by remember { mutableStateOf(initial?.user ?: "") }
    var pass by remember { mutableStateOf(initial?.pass ?: "") }

    val canSave = name.isNotBlank() && user.isNotBlank() && pass.isNotBlank()

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(if (initial == null) "Nova entrada" else "Editar entrada") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = name, onValueChange = { name = it },
                    label = { Text("Nome") }, singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                OutlinedTextField(
                    value = user, onValueChange = { user = it },
                    label = { Text("Usuário") }, singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                OutlinedTextField(
                    value = pass, onValueChange = { pass = it },
                    label = { Text("Senha") }, singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth()
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = { onConfirm(name.trim(), user.trim(), pass) },
                enabled = canSave
            ) { Text("Salvar") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancelar") }
        }
    )
}
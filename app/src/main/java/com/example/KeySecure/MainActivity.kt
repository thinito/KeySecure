package com.example.KeySecure

import android.os.Bundle
import android.view.WindowManager
import android.widget.Toast
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity

// Compose — foundation
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll

// Compose — material
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.*

// Compose — runtime
import androidx.compose.runtime.*
import androidx.compose.runtime.getValue

// Compose — ui
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp

// AndroidX
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.compose.collectAsStateWithLifecycle

// Projeto
import com.example.KeySecure.data.EntryItem
import com.example.KeySecure.data.SecurityPolicy
import com.example.KeySecure.data.VaultState
import com.example.KeySecure.ui.*
import com.example.KeySecure.util.ClipboardUtil

class MainActivity : AppCompatActivity() {

    private val unlockVm: UnlockViewModel by viewModels()
    private val vaultVm: VaultViewModel by viewModels()
    private val setupVm: SetupViewModel by viewModels()

    private val keyApp: KeySecureApp get() = application as KeySecureApp

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
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

// ---------------------------------------------------------------------------
// RootScreen
// ---------------------------------------------------------------------------
@Composable
private fun RootScreen(
    unlockVm: UnlockViewModel,
    vaultVm: VaultViewModel,
    setupVm: SetupViewModel,
    keyApp: KeySecureApp
) {
    // ✅ Fonte única de verdade: um único StateFlow<VaultState>
    val vaultState by keyApp.vaultRepository.state.collectAsStateWithLifecycle()
    val setupState by setupVm.state.collectAsStateWithLifecycle()

    // SetupScreen aparece se: o cofre não existe OU se o enrollment biométrico
    // pós-create está pendente (o `state` já virou Unlocked nesse instante).
    val showSetup = vaultState is VaultState.NotCreated ||
            setupState.pendingBiometricEnroll

    when {
        showSetup -> SetupScreen(setupVm, keyApp, setupState)
        vaultState is VaultState.Unlocked -> VaultScreen(vaultVm)
        else -> UnlockScreen(unlockVm, keyApp)
    }
}

// ---------------------------------------------------------------------------
// UnlockScreen
// ---------------------------------------------------------------------------
@Composable
private fun UnlockScreen(vm: UnlockViewModel, keyApp: KeySecureApp) {
    val state by vm.state.collectAsStateWithLifecycle()
    val context = LocalContext.current
    val activity = context as? FragmentActivity

    val hasBiometric = remember { keyApp.vaultRepository.hasBiometricEnrollment() }
    val biometricAvailable = remember { BiometricHelper.isAvailable(context) }
    val showBiometric = hasBiometric && biometricAvailable && activity != null

    val canSubmit = !state.isLocked && !state.isProcessing && (
            if (state.usePhrase) SecurityPolicy.isWellFormedPassphrase(state.phrase)
            else SecurityPolicy.isWellFormedPin(state.pin)
            )

    Column(
        Modifier
            .fillMaxSize()
            .safeDrawingPadding()
            .padding(24.dp),
        verticalArrangement = Arrangement.Center
    ) {
        Text(
            stringResource(R.string.unlock_title),
            style = MaterialTheme.typography.headlineMedium
        )
        Spacer(Modifier.height(16.dp))

        if (state.usePhrase) {
            OutlinedTextField(
                value = state.phrase,
                onValueChange = vm::onPhraseChange,
                label = { Text(stringResource(R.string.unlock_phrase_hint)) },
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.Password,
                    imeAction = ImeAction.Done
                ),
                keyboardActions = KeyboardActions(onDone = { if (canSubmit) vm.submit() }),
                singleLine = true,
                isError = state.error != null,
                enabled = !state.isLocked && !state.isProcessing,
                modifier = Modifier.fillMaxWidth()
            )
        } else {
            OutlinedTextField(
                value = state.pin,
                onValueChange = vm::onPinChange,
                label = {
                    Text(stringResource(
                        R.string.unlock_pin_hint,
                        SecurityPolicy.MIN_PIN_LENGTH
                    ))
                },
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.NumberPassword,
                    imeAction = ImeAction.Done
                ),
                keyboardActions = KeyboardActions(onDone = { if (canSubmit) vm.submit() }),
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
            Text(
                stringResource(R.string.error_locked_out, state.lockoutRemainingSec),
                color = MaterialTheme.colorScheme.error
            )
        }

        Spacer(Modifier.height(16.dp))
        Button(
            onClick = vm::submit,
            enabled = canSubmit,
            modifier = Modifier.fillMaxWidth()
        ) {
            if (state.isProcessing) {
                CircularProgressIndicator(
                    modifier = Modifier.size(18.dp),
                    strokeWidth = 2.dp,
                    color = MaterialTheme.colorScheme.onPrimary
                )
                Spacer(Modifier.width(8.dp))
                Text(stringResource(R.string.unlock_checking))
            } else {
                Text(stringResource(R.string.unlock_button))
            }
        }

        if (showBiometric) {
            Spacer(Modifier.height(8.dp))
            OutlinedButton(
                onClick = {
                    val iv = keyApp.vaultRepository.getBiometricIv()
                    if (iv == null) {
                        Toast.makeText(
                            context,
                            context.getString(R.string.biometric_unavailable),
                            Toast.LENGTH_SHORT
                        ).show()
                        return@OutlinedButton
                    }
                    BiometricHelper.promptForUnlock(
                        activity = activity!!,
                        keystore = keyApp.keystore,
                        iv = iv,
                        onSuccess = { cipher ->
                            val result = keyApp.vaultRepository.unlockWithKeystoreCipher(cipher)
                            if (result !is UnlockResult.Success) {
                                Toast.makeText(
                                    context,
                                    context.getString(R.string.error_unexpected),
                                    Toast.LENGTH_LONG
                                ).show()
                            }
                        },
                        onInvalidated = {
                            keyApp.vaultRepository.disableBiometric()
                            Toast.makeText(
                                context,
                                context.getString(R.string.biometric_invalidated),
                                Toast.LENGTH_LONG
                            ).show()
                        },
                        onError = { msg ->
                            Toast.makeText(
                                context,
                                context.getString(R.string.biometric_error, msg),
                                Toast.LENGTH_LONG
                            ).show()
                        }
                    )
                },
                enabled = !state.isLocked && !state.isProcessing,
                modifier = Modifier.fillMaxWidth()
            ) { Text(stringResource(R.string.unlock_biometric)) }
        }

        TextButton(
            onClick = vm::toggleUsePhrase,
            enabled = !state.isProcessing,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(stringResource(
                if (state.usePhrase) R.string.unlock_use_pin
                else R.string.unlock_use_phrase
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// SetupScreen
// ---------------------------------------------------------------------------
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
                    val result = keyApp.vaultRepository.enrollBiometric(cipher)
                    if (result !is UnlockResult.Success) {
                        Toast.makeText(
                            context,
                            context.getString(R.string.error_unexpected),
                            Toast.LENGTH_LONG
                        ).show()
                    }
                    vm.finishBiometricEnroll()
                },
                onError = { msg ->
                    Toast.makeText(
                        context,
                        context.getString(R.string.biometric_error, msg),
                        Toast.LENGTH_LONG
                    ).show()
                    vm.finishBiometricEnroll()
                }
            )
        }
    }

    Column(
        Modifier
            .fillMaxSize()
            .safeDrawingPadding()
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        verticalArrangement = Arrangement.Center
    ) {
        Text(
            stringResource(R.string.setup_title),
            style = MaterialTheme.typography.headlineMedium
        )
        Spacer(Modifier.height(16.dp))

        // 1) PIN
        OutlinedTextField(
            value = state.pin,
            onValueChange = vm::onPinChange,
            label = { Text(stringResource(R.string.setup_pin_hint)) },
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(
                keyboardType = KeyboardType.NumberPassword,
                imeAction = ImeAction.Next
            ),
            singleLine = true,
            isError = state.error != null,
            enabled = !state.isProcessing && !state.done,
            modifier = Modifier.fillMaxWidth()
        )
        Spacer(Modifier.height(8.dp))

        // 2) Confirmar PIN
        OutlinedTextField(
            value = state.confirmPin,
            onValueChange = vm::onConfirmPinChange,
            label = { Text(stringResource(R.string.setup_confirm_pin_hint)) },
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(
                keyboardType = KeyboardType.NumberPassword,
                imeAction = ImeAction.Next
            ),
            singleLine = true,
            isError = state.error != null,
            enabled = !state.isProcessing && !state.done,
            modifier = Modifier.fillMaxWidth()
        )
        Spacer(Modifier.height(16.dp))

        // 3) Frase-chave
        OutlinedTextField(
            value = state.phrase,
            onValueChange = vm::onPhraseChange,
            label = { Text(stringResource(R.string.setup_phrase_hint)) },
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(
                keyboardType = KeyboardType.Password,
                imeAction = ImeAction.Next
            ),
            singleLine = true,
            isError = state.error != null,
            enabled = !state.isProcessing && !state.done,
            modifier = Modifier.fillMaxWidth()
        )
        Spacer(Modifier.height(8.dp))

        // 4) Confirmar frase-chave
        OutlinedTextField(
            value = state.confirmPhrase,
            onValueChange = vm::onConfirmPhraseChange,
            label = { Text(stringResource(R.string.setup_confirm_phrase_hint)) },
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(
                keyboardType = KeyboardType.Password,
                imeAction = ImeAction.Done
            ),
            keyboardActions = KeyboardActions(
                onDone = { if (state.canSubmit) vm.create() }
            ),
            singleLine = true,
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
            enabled = state.canSubmit,
            modifier = Modifier.fillMaxWidth()
        ) {
            if (state.isProcessing) {
                CircularProgressIndicator(
                    modifier = Modifier.size(18.dp),
                    strokeWidth = 2.dp,
                    color = MaterialTheme.colorScheme.onPrimary
                )
                Spacer(Modifier.width(8.dp))
                Text(stringResource(R.string.setup_creating))
            } else {
                Text(stringResource(R.string.setup_confirm))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// VaultScreen
// ---------------------------------------------------------------------------
@Composable
private fun VaultScreen(vm: VaultViewModel) {
    val context = LocalContext.current
    val entries by vm.entries.collectAsStateWithLifecycle()
    val lastError by vm.lastError.collectAsStateWithLifecycle()

    val snackbarHostState = remember { SnackbarHostState() }
    LaunchedEffect(lastError) {
        lastError?.let { snackbarHostState.showSnackbar(it); vm.clearError() }
    }

    var showEntryDialog by remember { mutableStateOf(false) }
    var editingEntry by remember { mutableStateOf<EntryItem?>(null) }
    var editingPassword by remember { mutableStateOf<String?>(null) }
    var pendingDelete by remember { mutableStateOf<EntryItem?>(null) }

    var showSettings by remember { mutableStateOf(false) }
    var showChangePin by remember { mutableStateOf(false) }
    var showChangePhrase by remember { mutableStateOf(false) }
    var showUpgrade by remember { mutableStateOf(false) }
    var needsUpgrade by remember { mutableStateOf(false) }

    LaunchedEffect(showSettings) {
        if (showSettings) needsUpgrade = vm.needsIterationUpgrade()
    }

    Scaffold(
        contentWindowInsets = WindowInsets.safeDrawing,
        snackbarHost = { SnackbarHost(snackbarHostState) }
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            Row(
                Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text(
                    "Cofre",
                    style = MaterialTheme.typography.headlineSmall,
                    modifier = Modifier.weight(1f)
                )
                IconButton(onClick = { showSettings = true }) {
                    Icon(Icons.Default.Settings, contentDescription = "Configurações")
                }
                Button(onClick = {
                    editingEntry = null
                    editingPassword = null
                    showEntryDialog = true
                }) { Text(stringResource(R.string.vault_add)) }
                OutlinedButton(onClick = {
                    vm.lock()
                    ClipboardUtil.clearNow(context)
                    Toast.makeText(
                        context,
                        context.getString(R.string.vault_locked_toast),
                        Toast.LENGTH_SHORT
                    ).show()
                }) { Text(stringResource(R.string.vault_lock)) }
            }
            HorizontalDivider()

            if (entries.isEmpty()) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Text(stringResource(R.string.vault_empty))
                        Spacer(Modifier.height(16.dp))
                        Button(onClick = {
                            editingEntry = null
                            editingPassword = null
                            showEntryDialog = true
                        }) { Text(stringResource(R.string.vault_add_entry)) }
                    }
                }
            } else {
                LazyColumn(Modifier.fillMaxSize(), contentPadding = PaddingValues(16.dp)) {
                    items(entries, key = { it.id }) { entry: EntryItem ->
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
                                vm.copyPassword(context, entry.id)
                                Toast.makeText(
                                    context,
                                    context.getString(R.string.vault_copied_toast),
                                    Toast.LENGTH_SHORT
                                ).show()
                            }) { Text(stringResource(R.string.vault_copy)) }
                            TextButton(onClick = {
                                editingEntry = entry
                                editingPassword = vm.getPasswordForEdit(entry.id)
                                showEntryDialog = true
                            }) { Text(stringResource(R.string.vault_edit)) }
                            TextButton(onClick = { pendingDelete = entry }) {
                                Text(
                                    stringResource(R.string.vault_delete),
                                    color = MaterialTheme.colorScheme.error
                                )
                            }
                        }
                        HorizontalDivider()
                    }
                }
            }
        }
    }

    // -------- Diálogo de entrada (add/edit) --------
    if (showEntryDialog) {
        EntryDialog(
            initial = editingEntry,
            initialPassword = editingPassword,
            onDismiss = {
                showEntryDialog = false
                editingEntry = null
                editingPassword = null
            },
            onSave = { name, user, pass ->
                val current = editingEntry
                val result: Result<Unit> = if (current == null) {
                    vm.add(name, user, pass).map { }
                } else {
                    vm.update(current.id, name, user, pass)
                }
                if (result.isSuccess) {
                    showEntryDialog = false
                    editingEntry = null
                    editingPassword = null
                }
                result
            }
        )
    }

    // -------- Confirmação de exclusão --------
    pendingDelete?.let { entry ->
        AlertDialog(
            onDismissRequest = { pendingDelete = null },
            title = { Text("Excluir entrada?") },
            text = { Text("A entrada '${entry.name}' será removida permanentemente.") },
            confirmButton = {
                TextButton(onClick = {
                    if (vm.delete(entry.id).isSuccess) pendingDelete = null
                }) {
                    Text(
                        stringResource(R.string.vault_delete),
                        color = MaterialTheme.colorScheme.error
                    )
                }
            },
            dismissButton = {
                TextButton(onClick = { pendingDelete = null }) {
                    Text(stringResource(R.string.action_cancel))
                }
            }
        )
    }

    // -------- Diálogo de configurações --------
    if (showSettings) {
        AlertDialog(
            onDismissRequest = { showSettings = false },
            title = { Text(stringResource(R.string.settings_title)) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    TextButton(
                        onClick = {
                            vm.resetOpState()
                            showSettings = false
                            showChangePin = true
                        },
                        modifier = Modifier.fillMaxWidth()
                    ) { Text(stringResource(R.string.settings_change_pin)) }

                    TextButton(
                        onClick = {
                            vm.resetOpState()
                            showSettings = false
                            showChangePhrase = true
                        },
                        modifier = Modifier.fillMaxWidth()
                    ) { Text(stringResource(R.string.settings_change_phrase)) }

                    if (needsUpgrade) {
                        HorizontalDivider()
                        Text(
                            stringResource(R.string.settings_upgrade_needed),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.primary
                        )
                        Text(
                            stringResource(R.string.settings_upgrade_hint),
                            style = MaterialTheme.typography.bodySmall
                        )
                        TextButton(
                            onClick = {
                                vm.resetOpState()
                                showSettings = false
                                showUpgrade = true
                            },
                            modifier = Modifier.fillMaxWidth()
                        ) { Text(stringResource(R.string.settings_upgrade_iterations)) }
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = { showSettings = false }) {
                    Text(stringResource(R.string.action_close))
                }
            }
        )
    }

    // -------- Trocar PIN --------
    if (showChangePin) {
        ChangePinDialog(vm = vm, onDismiss = { showChangePin = false })
    }

    // -------- Trocar frase --------
    if (showChangePhrase) {
        ChangePhraseDialog(vm = vm, onDismiss = { showChangePhrase = false })
    }

    // -------- Upgrade de iterações --------
    if (showUpgrade) {
        UpgradeIterationsDialog(vm = vm, onDismiss = { showUpgrade = false })
    }
}

// ---------------------------------------------------------------------------
// EntryDialog
// ---------------------------------------------------------------------------
@Composable
private fun EntryDialog(
    initial: EntryItem?,
    initialPassword: String?,
    onDismiss: () -> Unit,
    onSave: (name: String, user: String, pass: String) -> Result<Unit>
) {
    var name by remember { mutableStateOf(initial?.name ?: "") }
    var user by remember { mutableStateOf(initial?.user ?: "") }
    var pass by remember { mutableStateOf(initialPassword ?: "") }
    var localError by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }

    val canSave = !busy && name.isNotBlank() && user.isNotBlank() && pass.isNotBlank()

    fun submit() {
        if (!canSave) return
        busy = true
        localError = null
        val result = onSave(name.trim(), user.trim(), pass)
        result.onFailure { e ->
            localError = e.message ?: e.javaClass.simpleName
            busy = false
        }
        // Em sucesso, o caller fecha o diálogo.
    }

    AlertDialog(
        onDismissRequest = { if (!busy) onDismiss() },
        title = { Text(if (initial == null) "Nova entrada" else "Editar entrada") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = name, onValueChange = { name = it; localError = null },
                    label = { Text("Nome") }, singleLine = true,
                    enabled = !busy, modifier = Modifier.fillMaxWidth()
                )
                OutlinedTextField(
                    value = user, onValueChange = { user = it; localError = null },
                    label = { Text("Usuário") }, singleLine = true,
                    enabled = !busy, modifier = Modifier.fillMaxWidth()
                )
                OutlinedTextField(
                    value = pass, onValueChange = { pass = it; localError = null },
                    label = { Text("Senha") }, singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(
                        keyboardType = KeyboardType.Password,
                        imeAction = ImeAction.Done
                    ),
                    keyboardActions = KeyboardActions(onDone = { submit() }),
                    enabled = !busy, modifier = Modifier.fillMaxWidth()
                )
                localError?.let {
                    Spacer(Modifier.height(4.dp))
                    Text(it, color = MaterialTheme.colorScheme.error)
                }
            }
        },
        confirmButton = {
            TextButton(onClick = { submit() }, enabled = canSave) {
                Text(if (busy) "Salvando..." else "Salvar")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss, enabled = !busy) {
                Text(stringResource(R.string.action_cancel))
            }
        }
    )
}

// ---------------------------------------------------------------------------
// ChangePinDialog
// ---------------------------------------------------------------------------
@Composable
private fun ChangePinDialog(vm: VaultViewModel, onDismiss: () -> Unit) {
    val opState by vm.opState.collectAsStateWithLifecycle()
    var current by remember { mutableStateOf("") }
    var newPin by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }

    LaunchedEffect(opState.success) {
        if (opState.success) {
            vm.resetOpState()
            onDismiss()
        }
    }

    val canSave = !opState.isProcessing &&
            current.isNotEmpty() &&
            SecurityPolicy.isStrongPin(newPin) &&
            newPin == confirm

    AlertDialog(
        onDismissRequest = {
            if (!opState.isProcessing) {
                vm.resetOpState()
                onDismiss()
            }
        },
        title = { Text(stringResource(R.string.change_pin_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = current, onValueChange = { current = it },
                    label = { Text(stringResource(R.string.change_pin_current)) },
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                    singleLine = true, enabled = !opState.isProcessing,
                    modifier = Modifier.fillMaxWidth()
                )
                OutlinedTextField(
                    value = newPin, onValueChange = { newPin = it },
                    label = { Text(stringResource(R.string.change_pin_new)) },
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                    singleLine = true, enabled = !opState.isProcessing,
                    modifier = Modifier.fillMaxWidth()
                )
                OutlinedTextField(
                    value = confirm, onValueChange = { confirm = it },
                    label = { Text(stringResource(R.string.change_pin_confirm)) },
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                    singleLine = true, enabled = !opState.isProcessing,
                    modifier = Modifier.fillMaxWidth()
                )
                opState.error?.let {
                    Text(it, color = MaterialTheme.colorScheme.error)
                }
            }
        },
        confirmButton = {
            TextButton(
                onClick = { vm.changePin(current, newPin) },
                enabled = canSave
            ) {
                if (opState.isProcessing) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(18.dp),
                        strokeWidth = 2.dp
                    )
                } else {
                    Text(stringResource(R.string.action_save))
                }
            }
        },
        dismissButton = {
            TextButton(
                onClick = { vm.resetOpState(); onDismiss() },
                enabled = !opState.isProcessing
            ) { Text(stringResource(R.string.action_cancel)) }
        }
    )
}

// ---------------------------------------------------------------------------
// ChangePhraseDialog
// ---------------------------------------------------------------------------
@Composable
private fun ChangePhraseDialog(vm: VaultViewModel, onDismiss: () -> Unit) {
    val opState by vm.opState.collectAsStateWithLifecycle()
    var current by remember { mutableStateOf("") }
    var newPhrase by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }

    LaunchedEffect(opState.success) {
        if (opState.success) {
            vm.resetOpState()
            onDismiss()
        }
    }

    val canSave = !opState.isProcessing &&
            current.isNotEmpty() &&
            SecurityPolicy.isStrongPassphrase(newPhrase) &&
            newPhrase == confirm

    AlertDialog(
        onDismissRequest = {
            if (!opState.isProcessing) {
                vm.resetOpState()
                onDismiss()
            }
        },
        title = { Text(stringResource(R.string.change_phrase_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = current, onValueChange = { current = it },
                    label = { Text(stringResource(R.string.change_phrase_current)) },
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    singleLine = true, enabled = !opState.isProcessing,
                    modifier = Modifier.fillMaxWidth()
                )
                OutlinedTextField(
                    value = newPhrase, onValueChange = { newPhrase = it },
                    label = { Text(stringResource(R.string.change_phrase_new)) },
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    singleLine = true, enabled = !opState.isProcessing,
                    modifier = Modifier.fillMaxWidth()
                )
                OutlinedTextField(
                    value = confirm, onValueChange = { confirm = it },
                    label = { Text(stringResource(R.string.change_phrase_confirm)) },
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    singleLine = true, enabled = !opState.isProcessing,
                    modifier = Modifier.fillMaxWidth()
                )
                opState.error?.let {
                    Text(it, color = MaterialTheme.colorScheme.error)
                }
            }
        },
        confirmButton = {
            TextButton(
                onClick = { vm.changePassphrase(current, newPhrase) },
                enabled = canSave
            ) {
                if (opState.isProcessing) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(18.dp),
                        strokeWidth = 2.dp
                    )
                } else {
                    Text(stringResource(R.string.action_save))
                }
            }
        },
        dismissButton = {
            TextButton(
                onClick = { vm.resetOpState(); onDismiss() },
                enabled = !opState.isProcessing
            ) { Text(stringResource(R.string.action_cancel)) }
        }
    )
}

// ---------------------------------------------------------------------------
// UpgradeIterationsDialog
// ---------------------------------------------------------------------------
@Composable
private fun UpgradeIterationsDialog(vm: VaultViewModel, onDismiss: () -> Unit) {
    val opState by vm.opState.collectAsStateWithLifecycle()
    var pin by remember { mutableStateOf("") }
    var phrase by remember { mutableStateOf("") }

    LaunchedEffect(opState.success) {
        if (opState.success) {
            vm.resetOpState()
            onDismiss()
        }
    }

    val canSave = !opState.isProcessing && pin.isNotEmpty() && phrase.isNotEmpty()

    AlertDialog(
        onDismissRequest = {
            if (!opState.isProcessing) {
                vm.resetOpState()
                onDismiss()
            }
        },
        title = { Text(stringResource(R.string.upgrade_iterations_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    stringResource(R.string.upgrade_iterations_warning),
                    style = MaterialTheme.typography.bodySmall
                )
                OutlinedTextField(
                    value = pin, onValueChange = { pin = it },
                    label = { Text(stringResource(R.string.upgrade_iterations_pin)) },
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                    singleLine = true, enabled = !opState.isProcessing,
                    modifier = Modifier.fillMaxWidth()
                )
                OutlinedTextField(
                    value = phrase, onValueChange = { phrase = it },
                    label = { Text(stringResource(R.string.upgrade_iterations_phrase)) },
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    singleLine = true, enabled = !opState.isProcessing,
                    modifier = Modifier.fillMaxWidth()
                )
                opState.error?.let {
                    Text(it, color = MaterialTheme.colorScheme.error)
                }
            }
        },
        confirmButton = {
            TextButton(
                onClick = { vm.upgradeIterations(pin, phrase) },
                enabled = canSave
            ) {
                if (opState.isProcessing) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(18.dp),
                        strokeWidth = 2.dp
                    )
                } else {
                    Text(stringResource(R.string.action_save))
                }
            }
        },
        dismissButton = {
            TextButton(
                onClick = { vm.resetOpState(); onDismiss() },
                enabled = !opState.isProcessing
            ) { Text(stringResource(R.string.action_cancel)) }
        }
    )
}
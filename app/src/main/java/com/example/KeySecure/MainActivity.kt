package com.example.KeySecure

import android.os.Bundle
import android.view.WindowManager
import android.widget.Toast
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge                      // ← NOVO
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import com.example.KeySecure.data.EntryItem


// Compose — layout
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.layout.WindowInsets              // ← NOVO
import androidx.compose.foundation.layout.safeDrawing              // ← NOVO
import androidx.compose.foundation.layout.safeDrawingPadding       // ← NOVO
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll

// Compose — teclado
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Settings

// Compose — material
import androidx.compose.material3.*

// Compose — runtime
import androidx.compose.runtime.*
import androidx.compose.runtime.getValue

// Compose — UI
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
import com.example.KeySecure.data.SecurityPolicy
import com.example.KeySecure.data.VaultEntry
import com.example.KeySecure.ui.*
import com.example.KeySecure.util.ClipboardUtil

class MainActivity : AppCompatActivity() {

    private val unlockVm: UnlockViewModel by viewModels()
    private val vaultVm: VaultViewModel by viewModels()
    private val setupVm: SetupViewModel by viewModels()

    private val keyApp: KeySecureApp get() = application as KeySecureApp

    override fun onCreate(savedInstanceState: Bundle?) {
        // ✅ Edge-to-edge explícito: transparent bars + ícones com contraste.
        // Em API 35+ é forçado; em API < 35, isto ativa o mesmo comportamento.
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

// ---------------------------------------------------------------------------
// UnlockScreen — safeDrawingPadding respeita status/nav bar, IME e notch
// ---------------------------------------------------------------------------
@Composable
private fun UnlockScreen(vm: UnlockViewModel, keyApp: KeySecureApp) {
    val state by vm.state.collectAsStateWithLifecycle()
    val context = LocalContext.current
    val activity = context as? FragmentActivity

    val hasBiometric = remember { keyApp.vault.hasBiometricEnrollment() }
    val biometricAvailable = remember { BiometricHelper.isAvailable(context) }
    val showBiometric = hasBiometric && biometricAvailable && activity != null

    val canSubmit = !state.isLocked && !state.isProcessing && (
            if (state.usePhrase) SecurityPolicy.isWellFormedPassphrase(state.phrase)
            else SecurityPolicy.isWellFormedPin(state.pin)
            )

    Column(
        Modifier
            .fillMaxSize()
            .safeDrawingPadding()          // ← ADICIONADO
            .padding(24.dp),
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
            Text(stringResource(
                if (state.isProcessing) R.string.unlock_checking
                else R.string.unlock_button
            ))
        }

        if (showBiometric) {
            Spacer(Modifier.height(8.dp))
            OutlinedButton(
                onClick = {
                    val iv = keyApp.vault.getBiometricIv()
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
                            val result = keyApp.vault.unlockWithKeystoreCipher(cipher)
                            if (result !is UnlockResult.Success) {
                                Toast.makeText(
                                    context,
                                    context.getString(R.string.error_unexpected),
                                    Toast.LENGTH_LONG
                                ).show()
                            }
                        },
                        onInvalidated = {
                            keyApp.vault.disableBiometric()
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
// SetupScreen — safeDrawingPadding + verticalScroll (IME empurra o conteúdo)
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
                    val result = keyApp.vault.enrollBiometric(cipher)
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
            .safeDrawingPadding()                                  // ← ADICIONADO
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
            Text(stringResource(
                if (state.isProcessing) R.string.setup_creating
                else R.string.setup_confirm
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// VaultScreen — opera por EntryItem (sem pass no estado) e lê a senha on-demand
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

    var showDialog by remember { mutableStateOf(false) }
    var editingEntry by remember { mutableStateOf<EntryItem?>(null) }
    var editingPassword by remember { mutableStateOf<String?>(null) }
    var pendingDelete by remember { mutableStateOf<EntryItem?>(null) }

    // ✅ Novos estados dos diálogos de configurações
    var showSettings by remember { mutableStateOf(false) }
    var showChangePin by remember { mutableStateOf(false) }
    var showChangePhrase by remember { mutableStateOf(false) }
    var showUpgrade by remember { mutableStateOf(false) }
    var needsUpgrade by remember { mutableStateOf(false) }

    // Re-checa needsUpgrade ao abrir as configurações
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
                Text("Cofre", style = MaterialTheme.typography.headlineSmall, modifier = Modifier.weight(1f))
                IconButton(onClick = { showSettings = true }) {
                    Icon(Icons.Default.Settings, contentDescription = "Configurações")
                }
                Button(onClick = {
                    editingEntry = null; editingPassword = null; showDialog = true
                }) { Text(stringResource(R.string.vault_add)) }
                OutlinedButton(onClick = {
                    vm.lock()
                    ClipboardUtil.clearNow(context)
                    Toast.makeText(context, context.getString(R.string.vault_locked_toast), Toast.LENGTH_SHORT).show()
                }) { Text(stringResource(R.string.vault_lock)) }
            }
            HorizontalDivider()

            if (entries.isEmpty()) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Text(stringResource(R.string.vault_empty))
                        Spacer(Modifier.height(16.dp))
                        Button(onClick = {
                            editingEntry = null; editingPassword = null; showDialog = true
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
                                Toast.makeText(context, context.getString(R.string.vault_copied_toast), Toast.LENGTH_SHORT).show()
                            }) { Text(stringResource(R.string.vault_copy)) }
                            TextButton(onClick = {
                                editingEntry = entry
                                editingPassword = vm.getPasswordForEdit(entry.id)
                                showDialog = true
                            }) { Text(stringResource(R.string.vault_edit)) }
                            TextButton(onClick = { pendingDelete = entry }) {
                                Text(stringResource(R.string.vault_delete), color = MaterialTheme.colorScheme.error)
                            }
                        }
                        HorizontalDivider()
                    }
                }
            }
        }
    }

    // ---------- Diálogo de entrada ----------
    if (showDialog) {
        EntryDialog(
            initial = editingEntry,
            initialPassword = editingPassword,
            onDismiss = { showDialog = false; editingEntry = null; editingPassword = null },
            onSave = { name, user, pass ->
                val current = editingEntry
                val result: Result<Unit> = if (current == null) {
                    vm.add(name, user, pass).map { }
                } else {
                    vm.update(current.id, name, user, pass)
                }
                if (result.isSuccess) {
                    showDialog = false; editingEntry = null; editingPassword = null
                }
                result
            }
        )
    }

    // ---------- Confirmação de exclusão ----------
    pendingDelete?.let { entry ->
        AlertDialog(
            onDismissRequest = { pendingDelete = null },
            title = { Text("Excluir entrada?") },
            text = { Text("A entrada '${entry.name}' será removida permanentemente.") },
            confirmButton = {
                TextButton(onClick = {
                    if (vm.delete(entry.id).isSuccess) pendingDelete = null
                }) {
                    Text(stringResource(R.string.vault_delete), color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = {
                TextButton(onClick = { pendingDelete = null }) { Text(stringResource(R.string.action_cancel)) }
            }
        )
    }

    // ---------- Diálogo de configurações ----------
    if (showSettings) {
        AlertDialog(
            onDismissRequest = { showSettings = false },
            title = { Text(stringResource(R.string.settings_title)) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    TextButton(
                        onClick = { showSettings = false; showChangePin = true },
                        modifier = Modifier.fillMaxWidth()
                    ) { Text(stringResource(R.string.settings_change_pin)) }

                    TextButton(
                        onClick = { showSettings = false; showChangePhrase = true },
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
                            onClick = { showSettings = false; showUpgrade = true },
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

    // ---------- Diálogo: trocar PIN ----------
    if (showChangePin) {
        ChangePinDialog(
            onDismiss = { showChangePin = false },
            onConfirm = { current, new ->
                vm.changePin(current, new).isSuccess.also { ok ->
                    if (ok) showChangePin = false
                }
            }
        )
    }

    // ---------- Diálogo: trocar frase ----------
    if (showChangePhrase) {
        ChangePhraseDialog(
            onDismiss = { showChangePhrase = false },
            onConfirm = { current, new ->
                vm.changePassphrase(current, new).isSuccess.also { ok ->
                    if (ok) showChangePhrase = false
                }
            }
        )
    }

    // ---------- Diálogo: upgrade de iterações ----------
    if (showUpgrade) {
        UpgradeIterationsDialog(
            onDismiss = { showUpgrade = false },
            onConfirm = { pin, phrase ->
                vm.upgradeIterations(pin, phrase).isSuccess.also { ok ->
                    if (ok) {
                        showUpgrade = false
                        Toast.makeText(
                            context,
                            context.getString(R.string.upgrade_iterations_success),
                            Toast.LENGTH_LONG
                        ).show()
                    }
                }
            }
        )
    }
}

// ---------------------------------------------------------------------------
// ChangePinDialog
// ---------------------------------------------------------------------------
@Composable
private fun ChangePinDialog(
    onDismiss: () -> Unit,
    onConfirm: (current: String, new: String) -> Boolean
) {
    var current by remember { mutableStateOf("") }
    var newPin by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }

    val canSave = current.isNotEmpty() &&
            SecurityPolicy.isStrongPin(newPin) &&
            newPin == confirm

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.change_pin_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = current, onValueChange = { current = it; error = null },
                    label = { Text(stringResource(R.string.change_pin_current)) },
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                    singleLine = true, modifier = Modifier.fillMaxWidth()
                )
                OutlinedTextField(
                    value = newPin, onValueChange = { newPin = it; error = null },
                    label = { Text(stringResource(R.string.change_pin_new)) },
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                    singleLine = true, modifier = Modifier.fillMaxWidth()
                )
                OutlinedTextField(
                    value = confirm, onValueChange = { confirm = it; error = null },
                    label = { Text(stringResource(R.string.change_pin_confirm)) },
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                    singleLine = true, modifier = Modifier.fillMaxWidth()
                )
                error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    val ok = onConfirm(current, newPin)
                    if (!ok) error = "Falha ao alterar PIN"
                },
                enabled = canSave
            ) { Text(stringResource(R.string.action_save)) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.action_cancel)) }
        }
    )
}

// ---------------------------------------------------------------------------
// ChangePhraseDialog
// ---------------------------------------------------------------------------
@Composable
private fun ChangePhraseDialog(
    onDismiss: () -> Unit,
    onConfirm: (current: String, new: String) -> Boolean
) {
    var current by remember { mutableStateOf("") }
    var newPhrase by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }

    val canSave = current.isNotEmpty() &&
            SecurityPolicy.isStrongPassphrase(newPhrase) &&
            newPhrase == confirm

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.change_phrase_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = current, onValueChange = { current = it; error = null },
                    label = { Text(stringResource(R.string.change_phrase_current)) },
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    singleLine = true, modifier = Modifier.fillMaxWidth()
                )
                OutlinedTextField(
                    value = newPhrase, onValueChange = { newPhrase = it; error = null },
                    label = { Text(stringResource(R.string.change_phrase_new)) },
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    singleLine = true, modifier = Modifier.fillMaxWidth()
                )
                OutlinedTextField(
                    value = confirm, onValueChange = { confirm = it; error = null },
                    label = { Text(stringResource(R.string.change_phrase_confirm)) },
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    singleLine = true, modifier = Modifier.fillMaxWidth()
                )
                error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    val ok = onConfirm(current, newPhrase)
                    if (!ok) error = "Falha ao alterar frase"
                },
                enabled = canSave
            ) { Text(stringResource(R.string.action_save)) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.action_cancel)) }
        }
    )
}

// ---------------------------------------------------------------------------
// UpgradeIterationsDialog
// ---------------------------------------------------------------------------
@Composable
private fun UpgradeIterationsDialog(
    onDismiss: () -> Unit,
    onConfirm: (pin: String, phrase: String) -> Boolean
) {
    var pin by remember { mutableStateOf("") }
    var phrase by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }

    val canSave = pin.isNotEmpty() && phrase.isNotEmpty()

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.upgrade_iterations_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    stringResource(R.string.upgrade_iterations_warning),
                    style = MaterialTheme.typography.bodySmall
                )
                OutlinedTextField(
                    value = pin, onValueChange = { pin = it; error = null },
                    label = { Text(stringResource(R.string.upgrade_iterations_pin)) },
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                    singleLine = true, modifier = Modifier.fillMaxWidth()
                )
                OutlinedTextField(
                    value = phrase, onValueChange = { phrase = it; error = null },
                    label = { Text(stringResource(R.string.upgrade_iterations_phrase)) },
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    singleLine = true, modifier = Modifier.fillMaxWidth()
                )
                error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    val ok = onConfirm(pin, phrase)
                    if (!ok) error = "Falha ao atualizar iterações"
                },
                enabled = canSave
            ) { Text(stringResource(R.string.action_save)) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.action_cancel)) }
        }
    )
}
// ---------------------------------------------------------------------------
// EntryDialog — recebe EntryItem + senha lida on-demand
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
    // remember (NÃO rememberSaveable): segredo nunca vai para o Bundle.
    var pass by remember { mutableStateOf(initialPassword ?: "") }
    var localError by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }

    val canSave = !busy && name.isNotBlank() && user.isNotBlank() && pass.isNotBlank()

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
                    enabled = !busy, modifier = Modifier.fillMaxWidth()
                )
                localError?.let {
                    Spacer(Modifier.height(4.dp))
                    Text(it, color = MaterialTheme.colorScheme.error)
                }
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    busy = true; localError = null
                    val result = onSave(name.trim(), user.trim(), pass)
                    result.onFailure { e ->
                        localError = e.message ?: e.javaClass.simpleName
                        busy = false
                    }
                },
                enabled = canSave
            ) { Text(if (busy) "Salvando..." else "Salvar") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss, enabled = !busy) { Text("Cancelar") }
        }
    )
}
// ---------------------------------------------------------------------------
// EntryDialog
// ---------------------------------------------------------------------------
@Composable
private fun EntryDialog(
    initial: VaultEntry?,
    onDismiss: () -> Unit,
    onSave: (name: String, user: String, pass: String) -> Result<Unit>
) {
    var name by remember { mutableStateOf(initial?.name ?: "") }
    var user by remember { mutableStateOf(initial?.user ?: "") }
    var pass by remember { mutableStateOf(initial?.pass ?: "") }
    var localError by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }

    val canSave = !busy && name.isNotBlank() && user.isNotBlank() && pass.isNotBlank()

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
                    keyboardActions = KeyboardActions(
                        onDone = { if (canSave) {
                            busy = true; localError = null
                            val result = onSave(name.trim(), user.trim(), pass)
                            result.onFailure { e ->
                                localError = e.message ?: e.javaClass.simpleName
                                busy = false
                            }
                        } }
                    ),
                    enabled = !busy, modifier = Modifier.fillMaxWidth()
                )
                localError?.let {
                    Spacer(Modifier.height(4.dp))
                    Text(it, color = MaterialTheme.colorScheme.error)
                }
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    busy = true
                    localError = null
                    val result = onSave(name.trim(), user.trim(), pass)
                    result.onFailure { e ->
                        localError = e.message ?: e.javaClass.simpleName
                        busy = false
                    }
                },
                enabled = canSave
            ) { Text(if (busy) "Salvando..." else "Salvar") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss, enabled = !busy) { Text("Cancelar") }
        }
    )
}
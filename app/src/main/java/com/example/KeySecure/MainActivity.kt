package com.example.KeySecure

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import javax.crypto.Cipher


private val Matte = darkColorScheme(
    primary = Color(0xFF9DB4D6),
    onPrimary = Color(0xFF101418),
    primaryContainer = Color(0xFF2A3342),
    onPrimaryContainer = Color(0xFFD6E2F5),
    background = Color(0xFF121214),
    onBackground = Color(0xFFE3E3E8),
    surface = Color(0xFF121214),
    onSurface = Color(0xFFE3E3E8),
    surfaceVariant = Color(0xFF232328),
    onSurfaceVariant = Color(0xFFA0A0A8),
    surfaceContainerHigh = Color(0xFF1E1E22),
    surfaceContainerHighest = Color(0xFF26262B),
    outline = Color(0xFF3A3A40),
    error = Color(0xFFE07A7A)
)
class MainActivity : FragmentActivity() {
    private lateinit var vault: Vault
    private var st by mutableIntStateOf(0) // 0 setup, 1 bloqueado, 2 aberto

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        window.statusBarColor = 0xFF121214.toInt()
        window.navigationBarColor = 0xFF121214.toInt()
        vault = Vault(applicationContext)
        st = if (vault.exists()) 1 else 0
        setContent {
            MaterialTheme(colorScheme = Matte) {
                Surface(color = MaterialTheme.colorScheme.background) { App() }
            }
        }
    }

    override fun onStop() {
        super.onStop()
        if (st == 2) { vault.lock(); st = 1 }
    }
    private fun bio(title: String, c: Cipher, ok: (Cipher) -> Unit) {
        val p = BiometricPrompt(this, ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(r: BiometricPrompt.AuthenticationResult) {
                    ok(r.cryptoObject!!.cipher!!)
                }
            })
        p.authenticate(
            BiometricPrompt.PromptInfo.Builder().setTitle(title).setNegativeButtonText("Cancelar")
                .setAllowedAuthenticators(BIOMETRIC_STRONG).build(),
            BiometricPrompt.CryptoObject(c)
        )
    }

    @Composable fun App() {
        when (st) {
            0 -> Setup { st = 2 }
            1 -> Lock { st = 2 }
            else -> Home { vault.lock(); st = 1 }
        }
    }

    @Composable fun Field(v: String, l: String, pin: Boolean = false, hide: Boolean = true, on: (String) -> Unit) =
        OutlinedTextField(v, on, label = { Text(l) }, singleLine = true, modifier = Modifier.fillMaxWidth(),
            visualTransformation = if (hide) PasswordVisualTransformation() else VisualTransformation.None,
            keyboardOptions = KeyboardOptions(keyboardType = if (pin) KeyboardType.NumberPassword else KeyboardType.Text))

    @Composable fun Setup(done: () -> Unit) {
        var pin by remember { mutableStateOf("") }; var phrase by remember { mutableStateOf("") }
        Column(Modifier.padding(24.dp).fillMaxSize(), Arrangement.Center, horizontalAlignment = androidx.compose.ui.Alignment.CenterHorizontally) {
            Text("Criar cofre", style = MaterialTheme.typography.headlineMedium)
            Spacer(Modifier.height(16.dp))
            Field(pin, "PIN (mín. 4 dígitos)", pin = true) { pin = it }
            Field(phrase, "Texto-chave de criptografia (mín. 8)") { phrase = it }
            Text("Guarde o texto-chave: ele protege seus dados e não pode ser recuperado.",
                style = MaterialTheme.typography.bodySmall)
            Spacer(Modifier.height(16.dp))
            Button({ vault.create(pin, phrase); done() }, enabled = pin.length >= 10 && phrase.length >= 10) { Text("Criar") }
        }
    }

    

    @Composable fun Lock(done: () -> Unit) {
        var pin by remember { mutableStateOf("") }; var err by remember { mutableStateOf("") }
        Column(Modifier.padding(24.dp).fillMaxSize(), Arrangement.Center, horizontalAlignment = androidx.compose.ui.Alignment.CenterHorizontally) {
            Text("Desbloquear", style = MaterialTheme.typography.headlineMedium)
            Spacer(Modifier.height(16.dp))
            Field(pin, "PIN", pin = true) { pin = it }
            if (err.isNotEmpty()) Text(err, color = MaterialTheme.colorScheme.error)
            Spacer(Modifier.height(16.dp))
            Button({ if (vault.unlockPin(pin)) done() else { err = "PIN incorreto"; pin = "" } }) { Text("Entrar") }
            if (vault.bioEnabled()) TextButton({
                try { bio("Desbloquear cofre", Crypto.bioCipher(Cipher.DECRYPT_MODE, vault.bioIv())) { c ->
                    if (vault.unlockBio(c)) done() } }
                catch (e: Exception) { err = "Biometria indisponível, use o PIN" }
            }) { Text("Usar biometria") }
        }
    }
    @Composable
    fun UnlockScreen(viewModel: UnlockViewModel) {
        val state by viewModel.state.collectAsStateWithLifecycle()

        Column {
            OutlinedTextField(
                value = state.pin,
                onValueChange = { viewModel.onPinChange(it) },
                label = { Text("PIN (mínimo ${SecurityPolicy.MIN_PIN_LENGTH} dígitos)") },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                visualTransformation = PasswordVisualTransformation(),
                isError = state.error != null
            )
            state.error?.let { Text(it, color = MaterialTheme.colorScheme.error) }

            Button(
                enabled = SecurityPolicy.isValidPin(state.pin) && !state.isLocked,
                onClick = { viewModel.submitPin() }
            ) { Text("Desbloquear") }
        }
    }
    @OptIn(ExperimentalMaterial3Api::class)
    @Composable fun Home(lockNow: () -> Unit) {
        var adding by remember { mutableStateOf(false) }
        var bioOn by remember { mutableStateOf(vault.bioEnabled()) }
        val clip = ClipboardUtil.copySensitive(
            context = context,
            label = "senha",
            value = entry.pass,
            scope = rememberCoroutineScope()
        )
        val shown = remember { mutableStateListOf<Entry>() }
        Scaffold(
            topBar = { TopAppBar(title = { Text("Minhas senhas") }, actions = {
                if (!bioOn) TextButton({ bio("Ativar biometria", Crypto.bioCipher(Cipher.ENCRYPT_MODE)) { c -> vault.enableBio(c); bioOn = true } }) { Text("Biometria") }
                TextButton(lockNow) { Text("Bloquear") }
            }) },
            floatingActionButton = { FloatingActionButton({ adding = true }) { Text("+") } }
        ) { pad ->
            LazyColumn(Modifier.padding(pad).padding(12.dp)) {
                items(vault.entries.toList()) { e ->
                    Card(Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
                        Column(Modifier.padding(12.dp)) {
                            Text(e.site, style = MaterialTheme.typography.titleMedium)
                            Text(e.user)
                            Text(if (e in shown) e.pass else "••••••••")
                            Row {
                                TextButton({ if (e in shown) shown.remove(e) else shown.add(e) }) { Text(if (e in shown) "Ocultar" else "Mostrar") }
                                TextButton({ clip.setText(AnnotatedString(e.pass)) }) { Text("Copiar") }
                                TextButton({ vault.remove(e) }) { Text("Excluir") }
                            }
                        }
                    }
                }
            }
        }
        if (adding) {
            var site by remember { mutableStateOf("") }; var u by remember { mutableStateOf("") }; var p by remember { mutableStateOf("") }
            AlertDialog(onDismissRequest = { adding = false },
                title = { Text("Nova senha") },
                text = { Column { Field(site, "Site/App", hide = false) { site = it }; Field(u, "Usuário", hide = false) { u = it }; Field(p, "Senha") { p = it } } },
                confirmButton = { TextButton({ vault.add(Entry(site, u, p)); adding = false }, enabled = site.isNotBlank() && p.isNotBlank()) { Text("Salvar") } },
                dismissButton = { TextButton({ adding = false }) { Text("Cancelar") } })
        }
    }
}

class UnlockViewModel(app: Application) : AndroidViewModel(app) {
    private val tracker = AttemptTracker(app)

    fun submitPin() {
        viewModelScope.launch {
            if (tracker.isLockedOut()) {
                val secs = tracker.remainingLockoutMs() / 1000
                _state.update { it.copy(error = "Bloqueado. Tente em ${secs}s") }
                return@launch
            }
            if (vault.unlock(_state.value.pin.toCharArray())) {
                tracker.reset()
                pin.fill('\u0000')
                // navega para o cofre
            } else {
                tracker.registerFailure()
                _state.update { it.copy(pin = "", error = "PIN incorreto") }
                pin.fill('\u0000')

            }
        }
    }
}
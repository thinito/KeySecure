package com.example.KeySecure.data

/**
 * Estado único do cofre, consolidando `exists` e `unlocked`.
 *
 * Fonte única de verdade para UI e ViewModels:
 *  - [NotCreated]: não há `vault.json` → mostrar SetupScreen.
 *  - [Locked]:     há cofre, mas a master key não está em memória → UnlockScreen.
 *  - [Unlocked]:   cofre destrancado → VaultScreen.
 */
sealed class VaultState {
    object NotCreated : VaultState()
    object Locked : VaultState()
    object Unlocked : VaultState()
}
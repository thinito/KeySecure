# Preserva classes do Compose
-keep class androidx.compose.** { *; }
-dontwarn androidx.compose.**

# Preserva modelos de dados serializados (JSON)
-keep class com.thinito.keysecure.data.** { *; }

# Remove logs em release
-assumenosideeffects class android.util.Log {
    public static *** d(...);
    public static *** v(...);
    public static *** i(...);
}

# Ofusca nomes de classes e métodos
-repackageclasses ''
-allowaccessmodification
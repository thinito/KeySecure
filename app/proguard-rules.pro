# ---- Compose ----
-keep class androidx.compose.** { *; }
-dontwarn androidx.compose.**

# ---- Kotlinx Serialization (VaultEnvelope/VaultEntry) ----
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.**
-keepclassmembers class com.example.KeySecure.data.** {
    *** Companion;
    *** serializer(...);
}
-keepclasseswithmembers class com.example.KeySecure.data.** {
    kotlinx.serialization.KSerializer serializer(...);
}

# ---- Remove logs em release ----
-assumenosideeffects class android.util.Log {
    public static *** d(...);
    public static *** v(...);
    public static *** i(...);
    public static *** w(...);
    public static *** e(...);
}

# ---- Ofuscação ----
-repackageclasses ''
-allowaccessmodification
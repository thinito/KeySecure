# Kotlinx Serialization — preserva serializers gerados
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.**
-keepclassmembers class com.example.KeySecure.data.** {
    *** Companion;
    *** serializer(...);
}
-keepclasseswithmembers class com.example.KeySecure.data.** {
    kotlinx.serialization.KSerializer serializer(...);
}

# NÃO preservar androidx.compose.** — R8 já sabe o que fazer (item 23)

# Remover apenas logs verbosos (não remover Log.e nem Log.w)
-assumenosideeffects class android.util.Log {
    public static *** d(...);
    public static *** v(...);
}

-repackageclasses ''
-allowaccessmodification
plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    // Adicione:
    id("org.jetbrains.kotlin.plugin.compose")
}
kotlin {
    jvmToolchain(17)
}

android {
    namespace = "com.example.KeySecure"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.example.KeySecure"
        minSdk = 24
        targetSdk = 34
        versionCode = 2
        versionName = "1.1.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
        debug {
            isMinifyEnabled = false
        }
    }

    buildFeatures { compose = true }
}

dependencies {
    // Compose
    implementation(platform("androidx.compose:compose-bom:2024.09.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.activity:activity-compose:1.9.2")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.4")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.4")

    // DataStore
    implementation("androidx.datastore:datastore-preferences:1.1.1")

    // Coroutines
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")

    // Serialization (VaultEnvelope)
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.3")

    // Testes
    testImplementation("junit:junit:4.13.2")
}
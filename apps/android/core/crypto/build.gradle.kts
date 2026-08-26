plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "app.ollo.crypto"
    compileSdk = 35
    defaultConfig { minSdk = 26 }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}

dependencies {
    // Production engine: official libsignal for device sessions.
    // Account Ed25519 is Tink (real Ed25519). Do not mix with XEdDSA.
    implementation("org.signal:libsignal-client:0.58.1")
    implementation("com.google.crypto.tink:tink-android:1.16.1")
    testImplementation("junit:junit:4.13.2")
}

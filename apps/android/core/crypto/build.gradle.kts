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
    // Production engine: official libsignal. Do not replace with a homegrown ratchet.
    implementation("org.signal:libsignal-client:0.58.1")
    testImplementation("junit:junit:4.13.2")
}

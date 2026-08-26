# OllO Android

Kotlin + Jetpack Compose. Production crypto engine: official `libsignal-client`.
Local DB: SQLCipher in `noBackupFilesDir`. Key wrapping: Android Keystore
(StrongBox when available). `FLAG_SECURE` is on. Cloud backup of the DB is
excluded. `SessionHost` restores `SessionVault` on launch and fails closed
before OTP unless a bound libsignal engine emits `deviceRegistrationJson`.

## Build

Requires JDK 17 and Android SDK 35.

```bash
# generate wrapper once on a machine with Gradle
gradle wrapper --gradle-version 8.9
./gradlew :app:assembleDebug
./gradlew :app:assembleRelease :app:bundleRelease
```

Debug talks to `http://10.0.2.2:8080` (emulator → host). Release uses
`https://api.ollo.example` and certificate pins (configure in
`network_security_config` / OkHttp CertificatePinner before launch).

Signing keys are **not** in this repository. Configure
`OLLO_UPLOAD_STORE_FILE` via the CI secret store.

This Linux CI image does not ship the Android SDK; the project is complete
for a standard Android builder.

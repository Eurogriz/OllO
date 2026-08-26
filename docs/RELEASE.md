# Release

## Backend

```bash
npm ci
npm run test
npm run build
docker build -f infrastructure/docker/Dockerfile.server -t ollo-server:$TAG .
```

Artifacts must be reproducible: lockfile pinned, `SOURCE_DATE_EPOCH` set
in CI.

## Android

Requirements: JDK 17, Android SDK 35, build-tools 35.

```bash
cd apps/android
./gradlew :app:assembleRelease :app:bundleRelease
```

Outputs:

- `app/build/outputs/apk/release/app-release.apk` — sideload / internal
- `app/build/outputs/bundle/release/app-release.aab` — Play

Signing: upload key in the org HSM / Play App Signing. A debug keystore
is provided for local `assembleDebug` only.

R8 is on for release. Mapping files are archived (crash symbolication),
never shipped to clients.

Play Integrity is optional and off by default (privacy).

This CI image is Linux without the Android SDK; the Gradle project is
complete so a standard Android builder can produce the artifacts.

## iOS

Apple does not allow a universal sideload IPA analogous to an APK.

On **macOS with Xcode**:

```bash
cd apps/ios
xcodebuild -scheme Ollo -configuration Release \
  -archivePath build/Ollo.xcarchive archive
xcodebuild -exportArchive -archivePath build/Ollo.xcarchive \
  -exportOptionsPlist ExportOptions.plist \
  -exportPath build/export
```

`ExportOptions.plist` targets: `app-store` (TestFlight / App Store) or
`ad-hoc` / `enterprise` for internal devices.

Signing and provisioning live in the Apple developer account, not in git.
See `apps/ios/README.md`.

## Mobile config

| Flavor | API | Pins |
|---|---|---|
| debug | `http://10.0.2.2:8080` (emulator) / LAN | off |
| staging | staging URL | staging pins |
| release | production URL | production + backup pins |

## Checklist

- [ ] Changelog
- [ ] Crypto / auth tests green
- [ ] `OTP_DEV_REVEAL` impossible in the prod image
- [ ] Production binds `LibsignalEngine` (Unbound is still the default)
- [ ] Account proofs use Tink / CryptoKit Ed25519, not libsignal XEdDSA
- [ ] SMS / Redis / S3 configured (prod refuses `SMS_PROVIDER=none`)
- [ ] Independent audit / pentest / crypto review **signed** (this repo is not that)
- [ ] Migrations expand-only
- [ ] Staging smoke (register, send, group, attach, call signal)
- [ ] Mapping / dSYM archived
- [ ] Tag signed

# OllO iOS

SwiftUI client. Production crypto: official libsignal Swift package.
Local DB: SQLCipher via GRDB, file protection `.completeUntilFirstUserAuthentication`.
Keys: Keychain (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`), Secure Enclave
for the wrapping key when the device supports it.

Apple does not provide a universal sideload IPA analogous to an Android APK.

## Build (macOS + Xcode)

1. Open `Ollo.xcodeproj` (or create it from the sources in `Ollo/` with the
   shared `Package.swift` modules).
2. Set the development team and bundle id `app.ollo.messenger`.
3. Archive:

```bash
xcodebuild -scheme Ollo -configuration Release \
  -archivePath build/Ollo.xcarchive archive
xcodebuild -exportArchive -archivePath build/Ollo.xcarchive \
  -exportOptionsPlist ExportOptions.plist \
  -exportPath build/export
```

`ExportOptions.plist` method:

- `app-store` → TestFlight / App Store
- `ad-hoc` → listed devices
- `enterprise` → org distribution if you have the program

Provisioning profiles and signing certificates live in the Apple developer
account, never in git.

Push: APNs. Incoming calls: PushKit + CallKit (subject to current Apple policy).
Notification payloads contain no plaintext.

This environment is Linux and cannot produce a signed IPA.

# android-kotlin: white-label native Android authenticator

A minimal native Android authenticator app in Kotlin, meant to be rebranded
and shipped as your own. Single activity, classic Views, no Compose.

Status: code-written only. This example was **not compiled or run** in the
environment where it was authored (no Android SDK present). It is complete
enough that `gradle assembleDebug` should work with AGP 8.x and compileSdk
34, but expect to fix the usual first-build papercuts.

## What it does

- Lists enrolled accounts with live 6-digit codes, recomputed every second,
  with a remaining-time progress bar.
- Add account: paste an `otpauth://totp/...` URI into a dialog.
- Delete account: long-press an entry, confirm in a dialog.
- Secrets are stored in `EncryptedSharedPreferences` (AES-256, master key in
  the Android Keystore), never in plaintext on disk.

## Interop with 2fa-kit (important)

2fa-kit is TypeScript and cannot run inside this app. Instead, this example
reimplements the same open standard (RFC 6238 TOTP / RFC 4226 HOTP) natively
in Kotlin in `Totp.kt`, using `javax.crypto.Mac` and a hand-rolled base32
decoder. TOTP is an interoperable standard, so:

- Any `otpauth://` URI works here, including one produced by a server using
  2fa-kit's `buildUri()`, and including URIs from Google Authenticator-style
  enrolment pages.
- Codes this app displays are identical to what 2fa-kit's `totp()` /
  `verifyTotp()` computes server-side, so login verification just works.

Supported URI parameters: `secret` (required; lowercase, unpadded, or
spaced secrets accepted), `issuer`, `algorithm` (SHA1 default, SHA256 and
SHA512 supported), `digits` (default 6), `period` (default 30). Only
`otpauth://totp/` URIs are accepted; `hotp` URIs are rejected. The counter
is handled as a full 8-byte big-endian value (`Long`), so periods and
counters beyond 32 bits are correct.

## White-label it

Three spots, then done:

1. `branding.json` (this directory) - the canonical reference: `appName`,
   `issuer`, `packageSuffix`, `primaryColor`, `accentColor`, `logoPath`.
2. `app/src/main/java/com/acme/authenticator/Branding.kt` - the same values
   as Kotlin constants, actually read by the app. Keep both files in sync.
3. `app/src/main/res/drawable/ic_launcher.xml` - replace with your icon
   (or generate mipmaps via Android Studio's Image Asset tool and update
   `android:icon` in `AndroidManifest.xml`).

Then also update the mechanical spots that Android itself requires:

- `app/build.gradle`: `namespace` and `applicationId` to
  `com.<packageSuffix>.authenticator` (and rename the Java package
  directories to match).
- `app/src/main/res/values/strings.xml`: `app_name`.
- `app/src/main/res/values/colors.xml`: `primary` / `accent`.

## Build

Requires JDK 17+ and the Android SDK (compileSdk 34). There is no Gradle
wrapper checked in; use a system Gradle 8.x or open the folder in Android
Studio and let it sync.

```sh
gradle assembleDebug
# output: app/build/outputs/apk/debug/app-debug.apk
```

## Layout

```
branding.json                                  canonical whitelabel values
settings.gradle / build.gradle / gradle.properties
app/build.gradle                               module config, dependencies
app/src/main/AndroidManifest.xml
app/src/main/java/com/acme/authenticator/
    Branding.kt       whitelabel constants (mirrors branding.json)
    Totp.kt           RFC 6238/4226 core: base32 decode, HMAC, truncation
    OtpAuthUri.kt     otpauth://totp/ URI parsing
    AccountStore.kt   EncryptedSharedPreferences persistence
    MainActivity.kt   account list, per-second ticker, add/delete dialogs
app/src/main/res/     layouts, strings, colors, theme, placeholder icon
```

## Notes

- The add-account flow pastes a URI; QR scanning is intentionally left out
  to keep the codebase small (add ML Kit or ZXing if you need it).
- The list refreshes by rebinding every second; fine for a sample with a
  handful of accounts, not a pattern for heavy lists.

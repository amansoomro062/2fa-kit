# Flutter white-label authenticator example

A minimal, white-label TOTP authenticator app in Flutter (Dart). It lists
accounts, shows live 6-digit codes with a per-second countdown, adds accounts
by pasting an `otpauth://` URI, and deletes them with a confirmation dialog.

## Status

**Not compiled or run in the environment where this example was written** -
no Flutter or Dart SDK was installed there. The Dart code was written against
Flutter 3 / Dart 3 APIs and the TOTP logic mirrors the RFC 6238 reference
vectors, but you should run `flutter test` and `flutter run` on your own
machine before relying on it. See "Run it" below.

## Interop with 2fa-kit (important)

[2fa-kit](https://www.npmjs.com/package/2fa-kit) is a TypeScript library and
**cannot run inside this Flutter app**. Nothing in this example imports or
wraps it. Instead, `lib/totp.dart` reimplements the same open standard
(RFC 6238 TOTP / RFC 4226 HOTP) natively in Dart, using `package:crypto` for
HMAC. Because both sides implement the same standard, codes generated here
match codes verified by any server using 2fa-kit, given the same secret,
algorithm, digits, and period. Defaults also match: SHA-1, 6 digits, 30
seconds.

Typical setup: a Node.js server uses 2fa-kit (`generateSecret`, `buildUri`)
to enrol users, the user pastes or scans the resulting `otpauth://` URI into
this app, and the server later checks the typed code with `verifyTotp`.

## Layout

```
branding.json        white-label config: app name, issuer, colors, logo path
lib/main.dart        single-screen app, loads branding, account list UI
lib/totp.dart        base32 decode + HOTP/TOTP (RFC 4226/6238), no UI deps
lib/otpauth.dart     otpauth:// URI parser
test/totp_test.dart  RFC 6238 SHA-1 test vectors
pubspec.yaml         dependencies: crypto, flutter_secure_storage
```

## White-labeling

The app reads `branding.json` at startup via `rootBundle` (it is declared as
an asset in `pubspec.yaml`). To rebrand:

1. Edit `branding.json` - `appName`, `issuer`, `primaryColor`, `accentColor`
   (hex strings), `logoPath`.
2. Replace the app icon the usual Flutter way (`flutter_launcher_icons` or
   by hand in the platform folders).
3. If you ship a logo, put the file at `logoPath` and add it to the `assets`
   list in `pubspec.yaml`.

No Dart code changes are needed for a rebrand.

Compile-time alternative: if you would rather bake branding in at build time
than ship a JSON asset, `--dart-define` is simpler, e.g.
`flutter run --dart-define=APP_NAME="Acme Authenticator" --dart-define=PRIMARY_COLOR=1E88E5`
and read the values with `String.fromEnvironment` / `int.fromEnvironment`.
This example wires up the JSON-asset approach only; pick one.

## Storage

Accounts are persisted with `flutter_secure_storage` (iOS Keychain / Android
Keystore-backed encrypted shared preferences). That is the right choice for
TOTP secrets on a real device. Check that plugin's setup notes when you add
platform folders - in particular Android needs `minSdkVersion 23` in
`android/app/build.gradle`.

If you are only experimenting, swapping to plain `shared_preferences` is a
two-line change in `lib/main.dart`, but do not ship that.

## Run it

This example intentionally contains no `android/` / `ios/` platform folders.
Generate them on first use:

```sh
cd examples/flutter
flutter create --platforms=android,ios .   # generate platform scaffolding
flutter pub get
flutter test                               # RFC 6238 vectors
flutter run                                # on a device or emulator
```

To add a real account, enrol on any service (or a 2fa-kit server) and copy
the `otpauth://` URI behind the QR code, then tap `+` in the app and paste it.

## Notes and limits

- TOTP only in the UI: HOTP (`counter`) URIs are parsed but rejected on add.
- SHA-256 / SHA-512, custom digits (6-8), and custom periods from URI
  parameters are supported by the TOTP core and honored when adding accounts.
- Secrets are accepted lowercase, unpadded, or with spaces, like the big
  authenticator apps display them.
- There is no QR scanner in this example to keep the dependency list short;
  paste the URI instead.

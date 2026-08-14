# iOS Authenticator Example (Swift, SwiftUI)

A minimal, white-label native iOS authenticator app: a list of accounts with
live 6-digit TOTP codes, a remaining-time indicator, adding accounts by
pasting an `otpauth://` URI, and swipe-to-delete with confirmation. Secrets
are stored in the iOS Keychain. No third-party dependencies.

## Status

Code-written, not compiled or run. This example was authored on a machine
without macOS/Xcode, so the sources have not been built or tested in this
environment. Expect to fix the occasional compiler nit on first build;
the TOTP/Keychain logic follows the RFCs and standard iOS APIs directly.

## Important interop note

2fa-kit is a TypeScript library and cannot run inside a native iOS app.
This example therefore does NOT use 2fa-kit at all. It reimplements the same
open standards natively in Swift (RFC 4648 base32, RFC 4226 HOTP, RFC 6238
TOTP, using CryptoKit for HMAC). Because both sides implement the same
standard, this app interoperates with any server that enrols users via
2fa-kit's `generateSecret()` / `buildUri()` / `verifyTotp()`: the codes this
app shows are the codes the server accepts.

Equivalent pieces:

| 2fa-kit (server, TypeScript) | This app (Swift) |
|---|---|
| `totp(secret, opts)` | `Totp.code(for:at:)` in `Sources/Totp.swift` |
| `base32Decode` | `Base32.decode` (same lowercase/padding/space tolerance) |
| `parseUri` | `OtpauthParser.parse` in `Sources/OtpauthParser.swift` |

Defaults match the ecosystem and 2fa-kit: SHA-1, 6 digits, 30 seconds.
`algorithm` (SHA1/SHA256/SHA512), `digits` (clamped to 6-8, the range
authenticator apps use), and `period` URI parameters are honored. Counters
are 64-bit, serialized as 8 bytes big-endian, so they stay correct past 32
bits.

## Requirements

- macOS with Xcode 15 or newer
- iOS 16+ deployment target (set in `project.yml`)

## Build

Option A: XcodeGen (a `project.yml` is included).

```sh
brew install xcodegen
cd examples/ios-swift
xcodegen
open AcmeAuthenticator.xcodeproj
```

Then pick a simulator or device and press Run.

Option B: create the project manually.

1. In Xcode: File -> New -> Project -> iOS -> App, SwiftUI lifecycle,
   deployment target iOS 16.
2. Delete the template's default files and drag `Sources/` into the project
   (make sure the target's Info.plist points at `Sources/Info.plist`, or
   paste its contents into the target's Info settings).
3. Run.

Run on a device (or simulator) and paste a URI produced on your server, e.g.:

```ts
import { generateSecret, buildUri } from "2fa-kit";
const secret = await generateSecret();
console.log(buildUri({ label: "alice@example.com", secret, issuer: "Acme" }));
```

Paste the printed `otpauth://totp/...` string into the app's Add screen.

## White-label / rebrand

Three spots:

1. `branding.json` (example root) - the single declarative source of truth:
   appName, issuer, bundleIdSuffix, colors, logo path. Placeholder values
   ship as "Acme Authenticator".
2. `Sources/Branding.swift` - the same values as compiled-in Swift constants.
   Keep it in sync with `branding.json` when you edit either one.
3. The app icon: drop a 1024x1024 PNG into
   `Sources/Assets.xcassets/AppIcon.appiconset` (path referenced by
   `logoPath`).

Also update `PRODUCT_BUNDLE_IDENTIFIER` in `project.yml` (or the target
settings in a manually created project) and `CFBundleDisplayName` in
`Sources/Info.plist`.

## Layout

```
branding.json                 white-label config (source of truth)
project.yml                   XcodeGen project definition
Sources/
  AuthenticatorApp.swift      app entry point
  Branding.swift              branding constants (mirrors branding.json)
  AccountsListView.swift      account list, live codes, swipe-to-delete
  AddAccountView.swift        paste otpauth:// URI form
  Account.swift               account model
  AccountStore.swift          observable store, persists via Keychain
  KeychainHelper.swift        kSecClassGenericPassword wrapper
  Totp.swift                  base32 decode + HOTP/TOTP core (CryptoKit)
  OtpauthParser.swift         otpauth:// URI parsing
  Info.plist                  app metadata
  Assets.xcassets/            asset catalog (app icon placeholder)
```

## Security notes

- Secrets live in the Keychain (`kSecClassGenericPassword`,
  `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`), never in UserDefaults
  or plain files.
- The whole account list is stored as one JSON item under the `accounts`
  key; deleting the app deletes it.
- This is a demo: there is no biometric/PIN lock, no QR scanning, no iCloud
  sync, and no HOTP (counter-based) account UI. Add those before shipping.

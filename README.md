# 2fa-kit

Add Google-Authenticator-style 2FA to your app. Zero dependencies, runs on
Node 20+, Bun, Deno, edge workers, and browsers.

[![npm version](https://img.shields.io/npm/v/2fa-kit)](https://www.npmjs.com/package/2fa-kit)
[![license](https://img.shields.io/badge/license-MIT-blue)](https://github.com/amansoomro062/2fa-kit/blob/main/LICENSE)

## What you need

- Node.js 20 or newer (nothing else to install, no native modules)
- One environment variable: `MASTER_KEY`, any long random string (used to
  encrypt stored secrets, same idea as a JWT secret)
- Two columns on your user record: `totp_secret` and `totp_salt`

## Install

```sh
npm install 2fa-kit
```

## The whole flow in two steps

```
 enrol:   server makes a secret --> user scans QR --> server stores it encrypted
 login:   user types 6-digit code --> server decrypts secret --> verify --> allow/deny
```

### Step 1: enrol a user

```ts
import { createVault, generateSecret, buildUri } from "2fa-kit";

const vault = await createVault(process.env.MASTER_KEY!);

const secret = await generateSecret();
const uri = buildUri({ label: user.email, secret, issuer: "Acme" });
// show `uri` as a QR code (see below) - the user scans it once

const { encrypted, salt } = await vault.encrypt(secret);
// save `encrypted` and `salt` on the user record
```

### Step 2: verify at login

```ts
import { verifyTotp } from "2fa-kit";

const secret = await vault.decrypt(user.totpSecret, user.totpSalt);
const ok = await verifyTotp(secret, codeFromLoginForm);
// true = allow, false = deny
```

That is the entire integration. Everything below is optional extras.

## Showing the QR code

The library gives you the URI; any QR library renders it:

```ts
import QRCode from "qrcode";
const dataUrl = await QRCode.toDataURL(uri); // <img src={dataUrl} />
```

## Extras

**Backup codes** - one-time recovery codes when the user loses their phone.
Store only the hashes:

```ts
const { codes, hashed } = await generateBackupCodes(); // show codes once, store hashed
```

**Import from Google Authenticator** - decode a "Transfer accounts" export QR:

```ts
const accounts = await parseMigrationUri(migrationUri); // -> ParsedOtpauth[]
```

## Examples

- [examples/server-node](./examples/server-node) - reference Node.js server (plain `node:http`) using the published package: enrol, verify, backup codes, recovery
- [examples/expo-authenticator](./examples/expo-authenticator) - React Native (Expo) authenticator app running 2fa-kit on-device via Web Crypto polyfills
- [examples/android-kotlin](./examples/android-kotlin) - white-label native Android authenticator (Kotlin, native RFC 6238 implementation)
- [examples/ios-swift](./examples/ios-swift) - white-label native iOS authenticator (Swift, SwiftUI + Keychain, native RFC 6238 implementation)
- [examples/flutter](./examples/flutter) - white-label Flutter authenticator (Dart, native RFC 6238 implementation)

The Kotlin, Swift, and Flutter examples cannot use 2fa-kit directly (it is
TypeScript); they reimplement the same RFC 6238 standard natively, so codes
interoperate with any 2fa-kit server. Each ships with a `branding.json` for
white-label customization.

## API

| Function | What it does |
|---|---|
| `generateSecret(opts?)` | Random base32 secret (default 32 chars) |
| `totp(secret, opts?)` | Current code + seconds remaining |
| `verifyTotp(secret, code, opts?)` | Check a code, tolerates +/-1 time step |
| `hotp(secret, counter, opts?)` | Counter-based code (RFC 4226) |
| `buildUri(opts)` | `otpauth://` URI for the QR code |
| `parseUri(uri)` | Parse an `otpauth://` URI back into parts |
| `createVault(masterKey)` | Encrypt/decrypt secrets (PBKDF2 + AES-256-GCM) |
| `generateSalt(length?)` | Random hex salt for the user record |
| `deriveKey(masterKey, salt)` | Derive the AES key directly (advanced) |
| `encryptSecret` / `decryptSecret` | Low-level encrypt/decrypt (advanced) |
| `generateBackupCodes(opts?)` | Recovery codes + SHA-256 hashes |
| `parseMigrationUri(uri)` | Decode a Google Authenticator export |
| `sha256Hex(string)` | SHA-256 hex digest helper |
| `base32Encode` / `base32Decode` | RFC 4648 base32 |

Full signatures and options are in the TypeScript types (`dist/index.d.ts`).

## Notes

- Defaults match the authenticator ecosystem: SHA-1, 6 digits, 30 seconds.
- Secrets are accepted lowercase, unpadded, or with spaces, just like the
  apps display them.
- The vault never stores plaintext: wrong master key or tampered data throws
  instead of decrypting.
- Losing `MASTER_KEY` makes stored secrets unrecoverable. Back it up.

## Examples

- [expo-authenticator](./examples/expo-authenticator) - a minimal Expo
  (React Native) authenticator app that generates TOTP codes fully
  on-device using 2fa-kit.

## License

MIT - see [LICENSE](./LICENSE).

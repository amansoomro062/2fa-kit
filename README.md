# 2fa-kit

Add Google-Authenticator-style 2FA to your app. Zero dependencies, runs on
Node 20+, Bun, Deno, edge workers, and browsers.

[![CI](https://github.com/amansoomro062/2fa-kit/actions/workflows/ci.yml/badge.svg)](https://github.com/amansoomro062/2fa-kit/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/2fa-kit)](https://www.npmjs.com/package/2fa-kit)
[![license](https://img.shields.io/badge/license-MIT-blue)](https://github.com/amansoomro062/2fa-kit/blob/main/LICENSE)

## What you need

- Node.js 20 or newer (nothing else to install, no native modules)
- One environment variable: `MASTER_KEY`, any long random string (used to
  encrypt stored secrets, same idea as a JWT secret)
- Three columns on your user record: `totp_secret`, `totp_salt`, and
  `totp_last_step` (an integer, for replay protection)

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
import { verifyTotpWithDelta } from "2fa-kit";

const secret = await vault.decrypt(user.totpSecret, user.totpSalt);
const { valid, step } = await verifyTotpWithDelta(secret, codeFromLoginForm);

if (!valid || step! <= user.totpLastStep) deny();
user.totpLastStep = step!; // persist, then allow
```

The `step` check is replay protection, and it is not optional: codes stay
valid for up to 90 seconds of clock drift, so a code that is only checked
with a boolean can be intercepted and used again. Storing the last accepted
step and requiring each login to beat it closes that door (RFC 6238 requires
it). `verifyTotp` still exists and returns a plain boolean for cases where
replay is handled elsewhere.

That is the entire integration. Everything below is optional extras.

## Showing the QR code

The library gives you the URI; any QR library renders it:

```ts
import QRCode from "qrcode";
const dataUrl = await QRCode.toDataURL(uri); // <img src={dataUrl} />
```

## Extras

**Backup codes** - one-time recovery codes when the user loses their phone.
Store only the hashes. Pass your master key so a leaked database row cannot
be brute-forced offline:

```ts
const { codes, hashed } = await generateBackupCodes({ key: masterKey });
// show `codes` once, store `hashed`

const { valid, remaining } = await verifyBackupCode(input, user.backupCodes, { key: masterKey });
if (!valid) deny();
user.backupCodes = remaining; // codes are single-use: persist, then allow
```

`verifyBackupCode` accepts any case, with or without dashes, and compares in
constant time.

**Import from Google Authenticator** - decode a "Transfer accounts" export QR:

```ts
const accounts = await parseMigrationUri(migrationUri); // -> ParsedOtpauth[]
```

## API

| Function | What it does |
|---|---|
| `generateSecret(opts?)` | Random base32 secret (default 32 chars) |
| `totp(secret, opts?)` | Current code + seconds remaining |
| `verifyTotp(secret, code, opts?)` | Check a code, tolerates +/-1 time step |
| `verifyTotpWithDelta(secret, code, opts?)` | Check a code and report the matched step, for replay protection |
| `hotp(secret, counter, opts?)` | Counter-based code (RFC 4226) |
| `buildUri(opts)` | `otpauth://` URI for the QR code |
| `parseUri(uri)` | Parse an `otpauth://` URI back into parts |
| `createVault(masterKey)` | Encrypt/decrypt secrets (PBKDF2 + AES-256-GCM) |
| `generateSalt(length?)` | Random hex salt for the user record |
| `deriveKey(masterKey, salt)` | Derive the AES key directly (advanced) |
| `encryptSecret` / `decryptSecret` | Low-level encrypt/decrypt (advanced) |
| `generateBackupCodes(opts?)` | Recovery codes + digests (HMAC when `key` is set) |
| `verifyBackupCode(input, hashed, opts?)` | Check a backup code and consume it |
| `parseMigrationUri(uri)` | Decode a Google Authenticator export |
| `sha256Hex(string)` / `hmacSha256Hex(key, string)` | Hex digest helpers |
| `base32Encode` / `base32Decode` | RFC 4648 base32 |

Full signatures and options are in the TypeScript types (`dist/index.d.ts`).

## Notes

- Defaults match the authenticator ecosystem: SHA-1, 6 digits, 30 seconds.
- Secrets are accepted lowercase, unpadded, or with spaces, just like the
  apps display them.
- The vault never stores plaintext: wrong master key or tampered data throws
  instead of decrypting.
- Losing `MASTER_KEY` makes stored secrets unrecoverable. Back it up.

## License

MIT - see [LICENSE](./LICENSE).

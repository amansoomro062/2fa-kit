# 2fa-kit

Zero-dependency 2FA toolkit: HOTP/TOTP, `otpauth://` URIs, encrypted secret
storage, Google Authenticator migration imports, and backup codes.

[![npm version](https://img.shields.io/npm/v/2fa-kit)](https://www.npmjs.com/package/2fa-kit)
[![license](https://img.shields.io/npm/l/2fa-kit)](https://github.com/amansoomro062/2fa-kit/blob/main/LICENSE)
[![zero dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)](https://www.npmjs.com/package/2fa-kit?activeTab=dependencies)

One code path runs everywhere - Node.js 20+, Bun, Deno, edge workers, and
browsers - because all cryptography goes through the standard Web Crypto API
(`globalThis.crypto.subtle`). No runtime dependencies, no platform shims.

## Why 2fa-kit?

- **`otplib`** is built around a plugin architecture: the core package does
  nothing until you wire up crypto and base32 plugins. `2fa-kit` is one package
  with zero configuration - the standard Web Crypto API is the only crypto
  backend, and it is always there.
- **`speakeasy`** is effectively unmaintained (no release in years) and
  predates modern runtimes. `2fa-kit` is actively maintained, ships TypeScript
  types, and runs on Node, Bun, Deno, edge workers, and browsers unchanged.
- **Encrypted storage built in.** Neither library answers "how do I store the
  secret?" `2fa-kit` ships a vault (PBKDF2 + AES-256-GCM) so secrets are never
  at rest in plaintext.

## Features

- RFC 4226 HOTP and RFC 6238 TOTP (SHA-1/SHA-256/SHA-512)
- `otpauth://` URI building and parsing for QR enrolment
- Encrypted-at-rest secret storage: PBKDF2-SHA-256 + AES-256-GCM vault
- Google Authenticator `otpauth-migration://` import (hand-rolled protobuf, no dependency)
- Single-use backup codes with SHA-256 digests for server-side storage
- Constant-time code comparison, BigInt counters, forgiving secret parsing
- ESM + CJS dual publish with TypeScript types
- Zero runtime dependencies, Web Crypto only

## Install

```sh
npm install 2fa-kit
```

## Quickstart: server-side 2FA in ~20 lines

```ts
import { buildUri, generateSecret, verifyTotp } from "2fa-kit";

// 1. Enrolment: create a secret and store it with the user record.
const secret = await generateSecret(); // "JBSWY3DPEHPK3PXP..." (32 chars)

// 2. Hand the user an otpauth:// URI to scan with any authenticator app
//    (render it as a QR code - see below).
const uri = buildUri({
  label: "alice@example.com",
  secret,
  issuer: "Acme",
});

// 3. Login: verify the 6-digit code the user types in.
const ok = await verifyTotp(secret, codeFromLoginForm); // +/-1 step window by default
if (!ok) {
  // reject the login
}
```

The quickstart stores the secret in plaintext for brevity. Don't do that in
production - use the vault:

```
ENROLMENT                                    YOUR DATABASE
─────────                                    ──────────────

generateSecret()
      │
      ▼
base32 secret ──► buildUri() ──► QR code ──► user scans with
      │                                       authenticator app
      ▼
vault.encrypt(secret) ──► { encrypted, salt } ──►  users table:
                                                   ┌───────────────────────────┐
                                                   │ id | salt | totp_secret   │
                                                   │  1 | 9f2c... | v1.k8Q...      │
                                                   └───────────────────────────┘
                                                   (salt + ENCRYPTED secret,
                                                    never plaintext)
```

```
LOGIN / VERIFY
──────────────

user reads 6-digit code from authenticator app
      │
      ▼
POST /login { code } ──► server loads salt + encrypted secret
                              │
                              ▼
                    vault.decrypt(encrypted, salt)
                              │
                              ▼
                    verifyTotp(secret, code)   // +/-1 step window
                              │
                    ┌─────────┴─────────┐
                    ▼                   ▼
                  allow               deny
```

## Storing secrets safely (the vault)

A TOTP secret is a permanent password: anyone who reads it from your database
can mint valid codes forever. The vault follows the same pattern as a JWT
signing secret - the server holds one master key in an environment variable,
and each user record stores a per-user salt plus the AES-256-GCM encrypted
secret:

```ts
import { createVault, generateSecret, buildUri, verifyTotp } from "2fa-kit";

// One vault per process. The master key comes from the environment,
// exactly like a JWT secret.
const vault = await createVault(process.env.MASTER_KEY!);

// Enrolment: encrypt with a fresh per-user salt.
const secret = await generateSecret();
const { encrypted, salt } = await vault.encrypt(secret);
// Persist on the user record, e.g. columns `totp_secret` and `totp_salt`:
//   INSERT INTO users (email, totp_secret, totp_salt) VALUES (?, ?, ?)
const uri = buildUri({ label: user.email, secret, issuer: "Acme" });

// Login: load salt + ciphertext from the user record, decrypt, verify.
const plaintext = await vault.decrypt(user.totpSecret, user.totpSalt);
const ok = await verifyTotp(plaintext, codeFromLoginForm);
```

Master-key guidance:

- Use a high-entropy random key (e.g. 32+ random bytes, hex or base64), not a
  human password.
- Keep it in an environment variable or a secrets manager. Never commit it.
- Rotating the master key means decrypting every stored secret with the old
  key and re-encrypting with the new one.
- Losing the master key makes all stored secrets unrecoverable - back it up
  like a database encryption key, because that is what it is.

## Rendering the QR code

`2fa-kit` deliberately does not render QR codes - `buildUri()` output feeds any QR
library. With [`qrcode`](https://www.npmjs.com/package/qrcode):

```ts
import { buildUri } from "2fa-kit";
import QRCode from "qrcode";

const uri = buildUri({ label: "alice@example.com", secret, issuer: "Acme" });
const dataUrl = await QRCode.toDataURL(uri); // <img src={dataUrl} />
```

## Importing accounts from Google Authenticator

Google Authenticator's "Transfer accounts" export produces an
`otpauth-migration://offline?data=...` URI (behind a QR code). `2fa-kit` decodes
the embedded protobuf payload - hand-rolled, no protobuf dependency:

```ts
import { parseMigrationUri, buildUri } from "2fa-kit";

const accounts = await parseMigrationUri(migrationUri);
for (const account of accounts) {
  console.log(account.label, account.type, account.algorithm, account.digits);
  // Re-emit as a standard otpauth:// URI if you want to re-enrol elsewhere:
  const uri = buildUri(account);
}
```

## Backup codes

Single-use recovery codes for when the authenticator device is lost. Show the
raw codes to the user once; store only the SHA-256 digests:

```ts
import { generateBackupCodes, sha256Hex } from "2fa-kit";

const { codes, hashed } = await generateBackupCodes(); // 10 codes, "XXXX-XXXX"
// show `codes` to the user, persist `hashed` in the database

// Later, when the user presents a recovery code:
const presented = "1A2B-3C4D";
const digest = await sha256Hex(presented);
const valid = storedDigests.includes(digest); // then delete that digest - codes are single-use
```

## API

### `generateSecret(opts?) => Promise<string>`

Generates a random base32 secret (no padding). `{ length }` is the number of
random bytes; default `20` yields a 32-character secret.

### `hotp(secret, counter, opts?) => Promise<string>`

RFC 4226 HOTP. `secret` is base32 (lowercase, padding and spaces tolerated);
`counter` is a non-negative integer (or `bigint`). Options: `{ digits }`
(default 6), `{ algorithm }` (`"SHA-1"` | `"SHA-256"` | `"SHA-512"`, default
`"SHA-1"`).

### `totp(secret, opts?) => Promise<{ code: string; remaining: number }>`

RFC 6238 TOTP. `remaining` is the number of seconds until the code expires.
Options: `{ timestamp }` (unix **milliseconds**, default `Date.now()`),
`{ period }` (seconds, default 30), `{ digits }` (default 6), `{ algorithm }`.

### `verifyTotp(secret, code, opts?) => Promise<boolean>`

Verifies a TOTP code, accepting codes within `+/-window` time steps (default
`window: 1`) to tolerate clock drift. Every candidate is compared with a
constant-time comparison. Same options as `totp`, plus `{ window }`.

### `buildUri(opts) => string`

Builds an `otpauth://` URI for QR enrolment:

```ts
buildUri({
  label: "alice@example.com",   // required
  secret,                       // required, base32
  issuer: "Acme",               // optional; also prefixes the label
  type: "totp",                 // "totp" (default) | "hotp"
  algorithm: "SHA256",          // optional (default = SHA1, omitted)
  digits: 8,                    // optional (default = 6, omitted)
  period: 60,                   // totp only (default = 30, omitted)
  counter: 0,                   // hotp only, required for hotp
});
```

### `parseUri(uri) => ParsedOtpauth`

Parses an `otpauth://totp` or `otpauth://hotp` URI:

```ts
interface ParsedOtpauth {
  type: "totp" | "hotp";
  label: string;        // label with any "Issuer:" prefix stripped
  issuer?: string;      // from the issuer param, else the label prefix
  secret: string;       // base32
  algorithm?: string;
  digits?: number;
  period?: number;      // totp
  counter?: number;     // hotp
}
```

Throws `TypeError` on malformed input (wrong protocol, missing `secret`, hotp
without `counter`, unknown type).

### `parseMigrationUri(uri) => Promise<ParsedOtpauth[]>`

Parses a Google Authenticator `otpauth-migration://offline?data=...` export
URI into one `ParsedOtpauth` per account. Algorithm and digit enums are mapped
to their string/number forms (`SHA1`/`SHA256`/`SHA512`/`MD5`, `6`/`8`);
unspecified values are omitted. Accounts without a secret are skipped.

### `generateBackupCodes(opts?) => Promise<{ codes: string[]; hashed: string[] }>`

Generates `{ count }` (default 10) backup codes of `{ length }` (default 8)
base32 characters, grouped with dashes (`1A2B-3C4D`). Returns the raw codes
plus their SHA-256 hex digests for server-side storage. Verify a presented
code with `sha256Hex(code)` and compare against stored digests.

### `createVault(masterKey, opts?) => Promise<Vault>`

Creates a vault bound to a master key - the primary encrypted-storage API.
`masterKey` is any string, typically from an environment variable;
`opts.iterations` overrides the PBKDF2 iteration count (see `deriveKey`).

```ts
const vault = await createVault(process.env.MASTER_KEY!);
const { encrypted, salt } = await vault.encrypt(secret); // fresh salt per call
const secret = await vault.decrypt(encrypted, salt);     // throws on wrong key/tampering
```

Each `encrypt()` call generates a fresh per-user salt and derives the key on
the spot - no key caching, no per-user state inside the vault.

### `generateSalt(length?) => Promise<string>`

Generates `length` random bytes (default 16) and returns them as lowercase
hex - 32 characters at the default length. Store the result on the user
record next to the encrypted secret.

### `deriveKey(masterKey, salt, opts?) => Promise<CryptoKey>`

Derives a non-extractable AES-256-GCM key from the master key and a hex salt
via PBKDF2-SHA-256. `opts.iterations` defaults to `210000` (the OWASP 2023
recommendation for SHA-256); must be a positive integer. Derivation is
deterministic: re-deriving from the persisted master key and salt reproduces
the key across restarts.

### `encryptSecret(secret, key) => Promise<string>`

Encrypts with AES-256-GCM and a random 12-byte IV. Returns
`"v1.<base64url(iv)>.<base64url(ciphertext+tag)>"` (url-safe base64, no
padding). The `v1.` prefix reserves room for future format changes.

### `decryptSecret(payload, key) => Promise<string>`

Parses the `v1.` format and decrypts. Throws an `Error` on a malformed
payload, and `"decryption failed: wrong key or corrupted data"` when the key
is wrong or the ciphertext has been tampered with (AES-GCM authenticates the
ciphertext).

### Lower-level exports

- `base32Encode(bytes) / base32Decode(string)` - RFC 4648 base32.
- `sha256Hex(string)` - SHA-256 hex digest helper.

## Notes

- Defaults follow the authenticator-app ecosystem: SHA-1, 6 digits, 30-second
  period.
- Secrets are accepted in any case, with or without padding, and may contain
  spaces - matching how authenticator apps display them.
- Counters beyond 32 bits are handled via `BigInt`, so far-future timestamps
  (e.g. the RFC 6238 `T=20000000000` test vector) work correctly.
- Vault payloads are versioned (`v1.` prefix) and use standard algorithms
  (PBKDF2-SHA-256, AES-256-GCM), so data is not locked into this library.
- Dual-published as ESM (`import`) and CJS (`require`) with TypeScript types.

## License

MIT - see [LICENSE](./LICENSE).

# otpk

Zero-dependency 2FA toolkit: HOTP/TOTP, `otpauth://` URIs, Google Authenticator
migration imports, and backup codes.

One code path runs everywhere — Node.js 20+, Bun, Deno, edge workers, and
browsers — because all cryptography goes through the standard Web Crypto API
(`globalThis.crypto.subtle`). No runtime dependencies, no platform shims.

```sh
npm install otpk
```

## Quickstart: server-side 2FA in ~20 lines

```ts
import { buildUri, generateSecret, verifyTotp } from "otpk";

// 1. Enrolment: create a secret and store it with the user record.
const secret = await generateSecret(); // "JBSWY3DPEHPK3PXP..." (32 chars)

// 2. Hand the user an otpauth:// URI to scan with any authenticator app
//    (render it as a QR code — see below).
const uri = buildUri({
  label: "alice@example.com",
  secret,
  issuer: "Acme",
});

// 3. Login: verify the 6-digit code the user types in.
const ok = await verifyTotp(secret, codeFromLoginForm); // ±1 step window by default
if (!ok) {
  // reject the login
}
```

## Rendering the QR code

`otpk` deliberately does not render QR codes — `buildUri()` output feeds any QR
library. With [`qrcode`](https://www.npmjs.com/package/qrcode):

```ts
import { buildUri } from "otpk";
import QRCode from "qrcode";

const uri = buildUri({ label: "alice@example.com", secret, issuer: "Acme" });
const dataUrl = await QRCode.toDataURL(uri); // <img src={dataUrl} />
```

## Importing accounts from Google Authenticator

Google Authenticator's "Transfer accounts" export produces an
`otpauth-migration://offline?data=...` URI (behind a QR code). `otpk` decodes
the embedded protobuf payload — hand-rolled, no protobuf dependency:

```ts
import { parseMigrationUri, buildUri } from "otpk";

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
import { generateBackupCodes, sha256Hex } from "otpk";

const { codes, hashed } = await generateBackupCodes(); // 10 codes, "XXXX-XXXX"
// show `codes` to the user, persist `hashed` in the database

// Later, when the user presents a recovery code:
const presented = "1A2B-3C4D";
const digest = await sha256Hex(presented);
const valid = storedDigests.includes(digest); // then delete that digest — codes are single-use
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

Verifies a TOTP code, accepting codes within `±window` time steps (default
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

### Lower-level exports

- `base32Encode(bytes) / base32Decode(string)` — RFC 4648 base32.
- `sha256Hex(string)` — SHA-256 hex digest helper.

## Notes

- Defaults follow the authenticator-app ecosystem: SHA-1, 6 digits, 30-second
  period.
- Secrets are accepted in any case, with or without padding, and may contain
  spaces — matching how authenticator apps display them.
- Counters beyond 32 bits are handled via `BigInt`, so far-future timestamps
  (e.g. the RFC 6238 `T=20000000000` test vector) work correctly.
- Dual-published as ESM (`import`) and CJS (`require`) with TypeScript types.

## License

MIT — see [LICENSE](./LICENSE).

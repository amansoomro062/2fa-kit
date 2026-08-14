# server-node example

A reference Node.js server showing how an integrator uses the
[2fa-kit](https://www.npmjs.com/package/2fa-kit) SDK server-side: enrolment,
TOTP verification, backup codes, and recovery.

Plain `node:http`, no framework, no dependencies besides `2fa-kit` itself.
Requires Node.js 20 or newer.

## Status

Tested in this environment: `npm install` pulled `2fa-kit@1.0.1` from the npm
registry, the server was started on Node v24, and every curl command below was
run against it with the expected results (valid code -> `{"ok":true}`, wrong
code -> `{"ok":false}`, backup-code recovery round-trip, and 429 after 5
failed attempts).

## Setup

```sh
cd examples/server-node
npm install
cp .env.example .env   # or set the variables yourself
npm start
```

The only required variable is `MASTER_KEY`, a long random string used to
encrypt stored secrets. Either copy `.env.example` to `.env` (the server reads
it with a tiny built-in parser, no dotenv dependency), or set it inline:

```sh
MASTER_KEY=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))") node index.js
```

Generate a persistent key once and reuse it; losing the key makes all stored
secrets unrecoverable. `PORT` defaults to 3000.

## The flow

```
 enrol:         POST /enrol        -> secret generated, encrypted, stored; otpauth URI returned
 scan:          user renders the URI as a QR code and scans it with an authenticator app
 login:         POST /verify       -> secret decrypted, code checked, allow/deny
 backup:        POST /backup-codes -> one-time codes returned, only hashes stored
 recovery:      POST /recover      -> hash compared, code deleted on success (single-use)
```

## Endpoints (copy-paste curl)

### 1. Enrol

```sh
curl -s -X POST http://localhost:3000/enrol \
  -H 'content-type: application/json' \
  -d '{"email":"alice@example.com"}'
```

Response:

```json
{"uri":"otpauth://totp/2fa-kit-demo%3Aalice%40example.com?secret=RB5K...&issuer=2fa-kit-demo"}
```

Render `uri` as a QR code (any QR library) and have the user scan it. The
server stores `{ email, encrypted, salt }` in `db.json`; the plaintext secret
never touches disk.

### 2. Verify

The user opens their authenticator and types the current 6-digit code:

```sh
curl -s -X POST http://localhost:3000/verify \
  -H 'content-type: application/json' \
  -d '{"email":"alice@example.com","code":"123456"}'
```

`{"ok":true}` allows the login, `{"ok":false}` denies it. After 5 failed
attempts for the same email within 10 minutes the server answers `429`:

```json
{"error":"too many failed attempts, try later"}
```

### 3. Backup codes

```sh
curl -s -X POST http://localhost:3000/backup-codes \
  -H 'content-type: application/json' \
  -d '{"email":"alice@example.com"}'
```

Response (shown to the user once; only the SHA-256 hashes are stored):

```json
{"codes":["XTF6-3PHK","IK4N-BTNQ","2QON-2SZE","LG6Z-RAUI","LMU7-QA2I","BXBU-LLJY","JN2V-M3ER","7F57-2LTE","4HF7-N5EV","3X55-LGQI"]}
```

### 4. Recover with a backup code

```sh
curl -s -X POST http://localhost:3000/recover \
  -H 'content-type: application/json' \
  -d '{"email":"alice@example.com","code":"XTF6-3PHK"}'
```

`{"ok":true}` on a match; the code is deleted immediately, so a second
`/recover` with the same code returns `{"ok":false}`.

## Where 2fa-kit is used

| Endpoint | 2fa-kit calls |
|---|---|
| `POST /enrol` | `generateSecret()` -> `buildUri({ label, secret, issuer })` -> `vault.encrypt(secret)` |
| `POST /verify` | `vault.decrypt(encrypted, salt)` -> `verifyTotp(secret, code)` |
| `POST /backup-codes` | `generateBackupCodes()` (returns raw codes + SHA-256 digests) |
| `POST /recover` | `sha256Hex(code)` compared against the stored digests |
| startup | `createVault(process.env.MASTER_KEY)` |

The vault encrypts secrets at rest with PBKDF2 + AES-256-GCM; a wrong master
key or tampered ciphertext throws instead of decrypting.

## Production notes

This is a reference implementation, not production code. Before shipping:

- Use a real database. `db.json` is a flat file with no locking and no
  concurrency guarantees.
- Put the server behind HTTPS. TOTP codes and backup codes are credentials.
- Use a real rate limiter (shared store, per IP and per account) instead of
  the in-memory map, which resets on restart and does not scale across
  processes.
- Never log secrets, codes, URIs, or master keys. Treat `db.json` and `MASTER_KEY`
  like password databases: restrict file permissions and keep them out of
  version control (`.gitignore` here already excludes `.env` and `db.json`).
- Back up `MASTER_KEY` somewhere safe; losing it makes every stored secret
  unrecoverable.

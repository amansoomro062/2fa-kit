# Contributing to 2fa-kit

Thanks for your interest. Issues and pull requests are welcome.

## Ground rules

- **Zero runtime dependencies.** This is the package's core promise. PRs that add a dependency will not be merged; if something seems to need one, open an issue first and we will find a dependency-free way or decide it does not belong here.
- **WebCrypto only.** All cryptography goes through `globalThis.crypto`. No `node:crypto` imports, no polyfills. The package must keep running unchanged on Node 20+, Bun, Deno, edge workers, and browsers.
- **Standards first.** Behaviour follows RFC 4226 (HOTP), RFC 6238 (TOTP), RFC 4648 (base32), and the Key URI Format. Cite the relevant section in your PR when behaviour is in question.
- **Security-sensitive code needs extra care.** Anything touching comparison, randomness, key derivation, or encryption should explain its reasoning in comments and come with tests. If you think you have found a vulnerability, do not open a public issue; see [SECURITY.md](SECURITY.md).

## Development setup

Node 20 or newer.

```sh
git clone https://github.com/amansoomro062/2fa-kit.git
cd 2fa-kit
npm install
npm test           # vitest
npm run typecheck  # tsc --noEmit
npm run build      # tsup -> dist/
```

## Project layout

```
src/
  base32.ts         RFC 4648 base32 encode/decode
  hotp.ts           RFC 4226 HOTP
  totp.ts           RFC 6238 TOTP
  verify.ts         verification with drift window, constant-time compare
  uri.ts            otpauth:// build and parse
  migration.ts      Google Authenticator migration import (hand-rolled protobuf reader)
  secrets-vault.ts  encrypted-at-rest secret storage (PBKDF2 + AES-256-GCM)
  backup-codes.ts   one-time recovery codes
  index.ts          public API surface
test/               one test file per module
```

## Pull requests

1. Open an issue first for anything beyond a small fix, so the approach is agreed before you write code.
2. Branch from `main`, keep the PR focused on one change.
3. Add or update tests. New OTP behaviour should be covered by RFC test vectors where they exist.
4. Make sure `npm test`, `npm run typecheck`, and `npm run build` all pass.
5. Update the README if the public API changed.

## Releases

Releases are cut from `main` by the maintainer. Version numbers follow semver; anything that changes the output of an existing function for the same input is a breaking change, including "fixing" code generation, because stored secrets and enrolled authenticators depend on it.

# Security Policy

2fa-kit is an authentication library, so security reports get priority over everything else.

## Reporting a vulnerability

Please do not open a public issue for anything you believe is exploitable.

Instead, use [GitHub private vulnerability reporting](https://github.com/amansoomro062/2fa-kit/security/advisories/new) on this repository. You will get an acknowledgement within 48 hours and a first assessment within 7 days.

If the report is valid:

- a fix is developed privately and released as soon as it is ready,
- a GitHub security advisory is published with credit to the reporter (unless you prefer to stay anonymous),
- affected versions are deprecated on npm where appropriate.

## Supported versions

| Version | Supported |
| ------- | --------- |
| 1.x     | yes       |

## Scope notes

Reports are especially welcome on:

- the HOTP/TOTP implementations and their verification paths (timing, window handling, truncation),
- the secrets vault (key derivation, AES-GCM usage, payload parsing),
- the base32 and protobuf parsers, which handle untrusted input,
- backup code generation and hashing.

Out of scope: vulnerabilities in applications that integrate 2fa-kit incorrectly (for example storing master keys in source control), and dependency advisories, since the package has no runtime dependencies.

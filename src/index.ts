import { base32Encode } from "./base32.js";

export { base32Encode, base32Decode } from "./base32.js";
export { hotp, type HotpOptions, type OtpAlgorithm } from "./hotp.js";
export { totp, type TotpOptions, type TotpResult } from "./totp.js";
export { verifyTotp, type VerifyTotpOptions } from "./verify.js";
export { buildUri, parseUri, type BuildUriOptions, type ParsedOtpauth } from "./uri.js";
export { parseMigrationUri } from "./migration.js";
export {
  generateBackupCodes,
  sha256Hex,
  type BackupCodes,
  type BackupCodesOptions,
} from "./backup-codes.js";

// Encrypted-at-rest secret storage (the "vault").
export {
  createVault,
  generateSalt,
  deriveKey,
  encryptSecret,
  decryptSecret,
  type Vault,
  type DeriveKeyOptions,
  type CreateVaultOptions,
} from "./secrets-vault.js";

export interface GenerateSecretOptions {
  /**
   * Number of random bytes to generate (default 20, which yields a
   * 32-character base32 secret).
   */
  length?: number;
}

/**
 * Generate a new random shared secret, base32-encoded.
 *
 * @returns an uppercase base32 string without padding, ready to hand to
 *          {@link buildUri} or an authenticator app's "enter key" form.
 */
export function generateSecret(opts: GenerateSecretOptions = {}): Promise<string> {
  const { length = 20 } = opts;
  if (!Number.isInteger(length) || length < 10) {
    throw new RangeError("length must be an integer of at least 10 bytes");
  }
  const crypto = globalThis.crypto;
  if (!crypto?.getRandomValues) {
    throw new Error(
      "globalThis.crypto is not available. Use Node.js >= 20, a modern browser, Deno, Bun, or an edge runtime.",
    );
  }
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  return Promise.resolve(base32Encode(bytes).replace(/=+$/, ""));
}

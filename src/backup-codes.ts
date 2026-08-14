/**
 * One-time backup codes, for account recovery when the authenticator device
 * is unavailable.
 *
 * Codes are generated with cryptographically secure randomness, formatted as
 * human-friendly groups (e.g. "ABCDE-FGHIJ"), and returned alongside hex
 * digests. Store only the digests server-side and verify with
 * {@link verifyBackupCode}, which normalises user input (case, dashes,
 * whitespace) and compares in constant time.
 *
 * Digests are computed over the canonical form of the code: uppercase with
 * dashes removed. Pass a `key` (your master key is a good choice) to use
 * HMAC-SHA-256 instead of plain SHA-256: with a keyed digest, a leaked
 * database row cannot be brute-forced offline without also having the key,
 * matching the guarantees of the secrets vault.
 */

import { base32Encode } from "./base32.js";
import { timingSafeEqual } from "./verify.js";

export interface BackupCodesOptions {
  /** Number of codes to generate (default 10). */
  count?: number;
  /** Number of characters per code before grouping (default 10). */
  length?: number;
  /**
   * Optional secret key. When set, digests are HMAC-SHA-256 keyed on it
   * instead of plain SHA-256, so leaked digests are useless without the key.
   * Use the same key (and the same setting) when verifying.
   */
  key?: string;
}

export interface BackupCodes {
  /** Raw codes, grouped with dashes, e.g. "ABCDE-FGHIJ". Show these to the user once. */
  codes: string[];
  /** Hex digests of the canonical codes, safe to store server-side. */
  hashed: string[];
}

export interface VerifyBackupCodeOptions {
  /** The key used at generation time, if any. Must match exactly. */
  key?: string;
}

export interface VerifyBackupCodeResult {
  /** Whether the input matched one of the stored digests. */
  valid: boolean;
  /**
   * The stored digests with the consumed one removed. Backup codes are
   * single-use: when `valid` is true, persist `remaining` in place of the
   * old list so the same code can never be accepted again.
   */
  remaining: string[];
}

function getCrypto(): Crypto {
  const crypto = globalThis.crypto;
  if (!crypto?.getRandomValues || !crypto.subtle) {
    throw new Error(
      "globalThis.crypto is not available. Use Node.js >= 20, a modern browser, Deno, Bun, or an edge runtime.",
    );
  }
  return crypto;
}

/** Insert dashes every `groupSize` characters: "ABCDEFGH" -> "ABCD-EFGH". */
export function groupCode(code: string, groupSize = 4): string {
  const groups: string[] = [];
  for (let i = 0; i < code.length; i += groupSize) {
    groups.push(code.slice(i, i + groupSize));
  }
  return groups.join("-");
}

/**
 * Canonical form used for hashing and verification: uppercase, with dashes
 * and whitespace removed. Users can type codes in any case, with or without
 * the dashes.
 */
export function normalizeBackupCode(input: string): string {
  return input.toUpperCase().replace(/[\s-]/g, "");
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = "";
  for (const byte of bytes) {
    hex += byte.toString(16).padStart(2, "0");
  }
  return hex;
}

/** SHA-256 hex digest of a UTF-8 string. */
export async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const digest = new Uint8Array(await getCrypto().subtle.digest("SHA-256", data as BufferSource));
  return bytesToHex(digest);
}

/** HMAC-SHA-256 hex digest of a UTF-8 string under a UTF-8 key. */
export async function hmacSha256Hex(key: string, input: string): Promise<string> {
  if (typeof key !== "string" || key.length === 0) {
    throw new TypeError("key must be a non-empty string");
  }
  const subtle = getCrypto().subtle;
  const cryptoKey = await subtle.importKey(
    "raw",
    new TextEncoder().encode(key) as BufferSource,
    { name: "HMAC", hash: { name: "SHA-256" } },
    false,
    ["sign"],
  );
  const mac = new Uint8Array(
    await subtle.sign("HMAC", cryptoKey, new TextEncoder().encode(input) as BufferSource),
  );
  return bytesToHex(mac);
}

async function digestCode(canonical: string, key: string | undefined): Promise<string> {
  return key === undefined ? sha256Hex(canonical) : hmacSha256Hex(key, canonical);
}

/**
 * Generate a set of single-use backup codes.
 *
 * The default of 10 characters gives 50 bits of entropy per code. Prefer
 * passing a `key` so stored digests cannot be brute-forced offline if the
 * database leaks.
 *
 * @returns the raw codes (show to the user once) and their hex digests
 *          (safe to persist server-side).
 */
export async function generateBackupCodes(opts: BackupCodesOptions = {}): Promise<BackupCodes> {
  const { count = 10, length = 10, key } = opts;
  if (!Number.isInteger(count) || count < 1) {
    throw new RangeError("count must be a positive integer");
  }
  if (!Number.isInteger(length) || length < 8) {
    throw new RangeError("length must be an integer of at least 8");
  }

  const crypto = getCrypto();
  const codes: string[] = [];
  const hashed: string[] = [];
  const bytesNeeded = Math.ceil((length * 5) / 8);
  const groupSize = length % 5 === 0 ? 5 : 4;

  for (let i = 0; i < count; i++) {
    const random = crypto.getRandomValues(new Uint8Array(bytesNeeded));
    const raw = base32Encode(random).replace(/=+$/, "").slice(0, length);
    codes.push(groupCode(raw, groupSize));
    hashed.push(await digestCode(raw, key));
  }

  return { codes, hashed };
}

/**
 * Verify a user-supplied backup code against the stored digests and consume
 * it.
 *
 * The input is normalised (uppercase, dashes and whitespace stripped) before
 * hashing, so "abcde-fghij" and "ABCDEFGHIJ" both verify. Every stored
 * digest is compared in constant time with no early exit.
 *
 * Backup codes are single-use: when the result is valid, persist
 * `remaining` in place of the old digest list.
 *
 * ```ts
 * const { valid, remaining } = await verifyBackupCode(input, user.backupCodes, { key });
 * if (!valid) deny();
 * user.backupCodes = remaining; // persist, then allow
 * ```
 */
export async function verifyBackupCode(
  input: string,
  hashed: readonly string[],
  opts: VerifyBackupCodeOptions = {},
): Promise<VerifyBackupCodeResult> {
  const canonical = normalizeBackupCode(input);
  const digests = [await digestCode(canonical, opts.key)];
  if (opts.key === undefined) {
    // v1.0.x digested the displayed form ("XXXX-XXXX", unkeyed). Accept those
    // stored digests too so existing users keep verifying after an upgrade.
    digests.push(await sha256Hex(groupCode(canonical, 4)));
  }

  let matchedIndex = -1;
  for (let i = 0; i < hashed.length; i++) {
    for (const digest of digests) {
      // no early exit: every stored digest is compared
      if (timingSafeEqual(digest, hashed[i]!) && matchedIndex === -1) {
        matchedIndex = i;
      }
    }
  }

  if (matchedIndex === -1) {
    return { valid: false, remaining: [...hashed] };
  }
  return { valid: true, remaining: hashed.filter((_, i) => i !== matchedIndex) };
}

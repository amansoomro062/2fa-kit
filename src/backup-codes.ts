/**
 * One-time backup codes, for account recovery when the authenticator device
 * is unavailable.
 *
 * Codes are generated with cryptographically secure randomness, formatted as
 * human-friendly groups (e.g. "1A2B-3C4D"), and returned alongside SHA-256
 * hex digests. Store only the digests server-side; to verify a presented
 * code, hash it the same way and compare against the stored digests.
 */

import { base32Encode } from "./base32.js";

export interface BackupCodesOptions {
  /** Number of codes to generate (default 10). */
  count?: number;
  /** Number of characters per code before grouping (default 8). */
  length?: number;
}

export interface BackupCodes {
  /** Raw codes, grouped with dashes, e.g. "1A2B-3C4D". Show these to the user once. */
  codes: string[];
  /** SHA-256 hex digests of the raw codes, safe to store server-side. */
  hashed: string[];
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

/** Insert dashes every 4 characters: "1A2B3C4D" -> "1A2B-3C4D". */
export function groupCode(code: string, groupSize = 4): string {
  const groups: string[] = [];
  for (let i = 0; i < code.length; i += groupSize) {
    groups.push(code.slice(i, i + groupSize));
  }
  return groups.join("-");
}

/** SHA-256 hex digest of a UTF-8 string. */
export async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const digest = new Uint8Array(await getCrypto().subtle.digest("SHA-256", data as BufferSource));
  let hex = "";
  for (const byte of digest) {
    hex += byte.toString(16).padStart(2, "0");
  }
  return hex;
}

/**
 * Generate a set of single-use backup codes.
 *
 * @returns the raw codes (show to the user once) and their SHA-256 hex
 *          digests (safe to persist server-side).
 */
export async function generateBackupCodes(opts: BackupCodesOptions = {}): Promise<BackupCodes> {
  const { count = 10, length = 8 } = opts;
  if (!Number.isInteger(count) || count < 1) {
    throw new RangeError("count must be a positive integer");
  }
  if (!Number.isInteger(length) || length < 4) {
    throw new RangeError("length must be an integer of at least 4");
  }

  const crypto = getCrypto();
  const codes: string[] = [];
  const hashed: string[] = [];
  const bytesNeeded = Math.ceil((length * 5) / 8);

  for (let i = 0; i < count; i++) {
    const random = crypto.getRandomValues(new Uint8Array(bytesNeeded));
    const raw = base32Encode(random).replace(/=+$/, "").slice(0, length);
    const code = groupCode(raw);
    codes.push(code);
    hashed.push(await sha256Hex(code));
  }

  return { codes, hashed };
}

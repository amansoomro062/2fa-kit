/**
 * Encrypted-at-rest storage for TOTP secrets.
 *
 * TOTP secrets should never be stored in plaintext: anyone who reads the
 * database can mint valid codes for every account. This module follows the
 * same pattern as a JWT signing secret — the server holds one master key in
 * an environment variable (or secrets manager), and each user record stores a
 * per-user salt plus the encrypted secret. Compromising the database alone
 * yields nothing usable without the master key.
 *
 * The master key is stretched with PBKDF2-SHA-256 (salted per user, so
 * identical master keys do not produce identical derived keys across users)
 * and secrets are encrypted with AES-256-GCM, which also authenticates the
 * ciphertext: tampering or a wrong key fails decryption instead of returning
 * garbage.
 *
 * Everything goes through `globalThis.crypto.subtle`, so it runs on
 * Node.js >= 20, Bun, Deno, edge workers, and browsers.
 */

export interface DeriveKeyOptions {
  /**
   * PBKDF2 iteration count (default 210000, the OWASP 2023 recommendation
   * for SHA-256). Lower values are faster but weaker; raise it over time as
   * hardware improves.
   */
  iterations?: number;
}

export interface Vault {
  /**
   * Encrypt a TOTP secret. Generates a fresh per-user salt and derives the
   * key on every call (stateless, no key caching).
   *
   * @returns the encrypted payload and the salt; persist both on the user record.
   */
  encrypt(secret: string): Promise<{ encrypted: string; salt: string }>;
  /**
   * Decrypt a payload previously produced by {@link Vault.encrypt}, using the
   * salt stored alongside it.
   */
  decrypt(encrypted: string, salt: string): Promise<string>;
}

export interface CreateVaultOptions {
  /** PBKDF2 iteration count passed through to {@link deriveKey}. */
  iterations?: number;
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

/** URL-safe base64 without padding. */
function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlDecode(input: string): Uint8Array {
  const base64 = input.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function hexToBytes(hex: string): Uint8Array {
  if (!/^[0-9a-f]*$/i.test(hex) || hex.length % 2 !== 0) {
    throw new TypeError("salt must be an even-length hex string");
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Generate a random per-user salt.
 *
 * @param length number of random bytes (default 16)
 * @returns the salt as lowercase hex — 32 characters at the default length.
 *          Store it alongside the encrypted secret on the user record.
 */
export function generateSalt(length = 16): Promise<string> {
  if (!Number.isInteger(length) || length < 1) {
    throw new RangeError("length must be a positive integer number of bytes");
  }
  const bytes = getCrypto().getRandomValues(new Uint8Array(length));
  let hex = "";
  for (const byte of bytes) {
    hex += byte.toString(16).padStart(2, "0");
  }
  return Promise.resolve(hex);
}

/**
 * Derive an AES-256-GCM key from the master key and a per-user salt.
 *
 * Uses PBKDF2-SHA-256 via `crypto.subtle.deriveKey`. The returned key is
 * non-extractable, so the raw key material cannot leave the crypto module.
 *
 * @param masterKey any string, typically from an environment variable
 * @param salt      hex string produced by {@link generateSalt}
 */
export async function deriveKey(
  masterKey: string,
  salt: string,
  opts: DeriveKeyOptions = {},
): Promise<CryptoKey> {
  const { iterations = 210_000 } = opts;
  if (!Number.isInteger(iterations) || iterations <= 0) {
    throw new RangeError("iterations must be a positive integer");
  }
  const crypto = getCrypto();
  const password = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(masterKey) as BufferSource,
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt: hexToBytes(salt) as BufferSource, iterations },
    password,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

/**
 * Encrypt a TOTP secret with AES-256-GCM and a random 12-byte IV.
 *
 * @returns `"v1.<base64url(iv)>.<base64url(ciphertext+tag)>"` — url-safe
 *          base64, no padding. The `v1.` prefix reserves room for future
 *          format changes.
 */
export async function encryptSecret(secret: string, key: CryptoKey): Promise<string> {
  const crypto = getCrypto();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv as BufferSource },
      key,
      new TextEncoder().encode(secret) as BufferSource,
    ),
  );
  return `v1.${base64UrlEncode(iv)}.${base64UrlEncode(ciphertext)}`;
}

/**
 * Decrypt a payload produced by {@link encryptSecret}.
 *
 * @throws Error on a malformed payload, a wrong key, or tampered ciphertext.
 */
export async function decryptSecret(payload: string, key: CryptoKey): Promise<string> {
  const parts = payload.split(".");
  if (parts.length !== 3 || parts[0] !== "v1") {
    throw new Error("malformed payload: expected \"v1.<iv>.<ciphertext>\"");
  }
  let iv: Uint8Array;
  let ciphertext: Uint8Array;
  try {
    iv = base64UrlDecode(parts[1]!);
    ciphertext = base64UrlDecode(parts[2]!);
  } catch {
    throw new Error("malformed payload: invalid base64url data");
  }
  try {
    const plaintext = await getCrypto().subtle.decrypt(
      { name: "AES-GCM", iv: iv as BufferSource },
      key,
      ciphertext as BufferSource,
    );
    return new TextDecoder().decode(plaintext);
  } catch {
    throw new Error("decryption failed: wrong key or corrupted data");
  }
}

/**
 * Create a vault bound to a master key. This is the primary API: one vault
 * per server process, one `encrypt`/`decrypt` pair per user.
 *
 * The master key should be a high-entropy random string held in an
 * environment variable or secrets manager — never committed to source
 * control. Rotating the master key means decrypting every stored secret with
 * the old key and re-encrypting with the new one.
 *
 * Each {@link Vault.encrypt} call generates a fresh salt and derives the key
 * on the spot — the vault holds no per-user state and caches nothing.
 */
export async function createVault(masterKey: string, opts: CreateVaultOptions = {}): Promise<Vault> {
  if (typeof masterKey !== "string" || masterKey.length === 0) {
    throw new TypeError("masterKey must be a non-empty string");
  }
  return {
    async encrypt(secret: string) {
      const salt = await generateSalt();
      const key = await deriveKey(masterKey, salt, opts);
      return { encrypted: await encryptSecret(secret, key), salt };
    },
    async decrypt(encrypted: string, salt: string) {
      const key = await deriveKey(masterKey, salt, opts);
      return decryptSecret(encrypted, key);
    },
  };
}

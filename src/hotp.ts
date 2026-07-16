import { base32Decode } from "./base32.js";

export type OtpAlgorithm = "SHA-1" | "SHA-256" | "SHA-512";

export interface HotpOptions {
  /** Number of digits in the code (default 6). */
  digits?: number;
  /** HMAC algorithm (default "SHA-1"). */
  algorithm?: OtpAlgorithm;
}

/** Number of bytes an HMAC produces for each supported algorithm. */
const HMAC_BYTES: Record<OtpAlgorithm, number> = {
  "SHA-1": 20,
  "SHA-256": 32,
  "SHA-512": 64,
};

function getSubtle(): SubtleCrypto {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new Error(
      "globalThis.crypto.subtle is not available. Use Node.js >= 20, a modern browser, Deno, Bun, or an edge runtime.",
    );
  }
  return subtle;
}

/** Serialize a counter to 8 bytes, big-endian. Safe beyond 32 bits. */
export function counterToBytes(counter: number | bigint): Uint8Array {
  if (typeof counter === "number" && (!Number.isSafeInteger(counter) || counter < 0)) {
    throw new RangeError("counter must be a non-negative safe integer");
  }
  let value = BigInt(counter);
  if (value < 0n || value > 0xffffffffffffffffn) {
    throw new RangeError("counter must fit in an unsigned 64-bit integer");
  }
  const bytes = new Uint8Array(8);
  for (let i = 7; i >= 0; i--) {
    bytes[i] = Number(value & 0xffn);
    value >>= 8n;
  }
  return bytes;
}

/**
 * Generate an HOTP code (RFC 4226).
 *
 * @param secret  base32-encoded shared secret (lowercase/padding/spaces tolerated)
 * @param counter monotonically increasing counter
 */
export async function hotp(
  secret: string,
  counter: number | bigint,
  opts: HotpOptions = {},
): Promise<string> {
  const { digits = 6, algorithm = "SHA-1" } = opts;
  if (!Number.isInteger(digits) || digits < 1 || digits > 10) {
    throw new RangeError("digits must be an integer between 1 and 10");
  }

  const subtle = getSubtle();
  const keyBytes = base32Decode(secret);
  const key = await subtle.importKey(
    "raw",
    keyBytes as BufferSource,
    { name: "HMAC", hash: { name: algorithm } },
    false,
    ["sign"],
  );
  const mac = new Uint8Array(await subtle.sign("HMAC", key, counterToBytes(counter) as BufferSource));

  // RFC 4226 dynamic truncation
  const offset = mac[mac.length - 1]! & 0x0f;
  const binary =
    (((mac[offset]! & 0x7f) << 24) |
      ((mac[offset + 1]! & 0xff) << 16) |
      ((mac[offset + 2]! & 0xff) << 8) |
      (mac[offset + 3]! & 0xff)) >>>
    0;

  const modulus = 10 ** digits;
  return (binary % modulus).toString().padStart(digits, "0");
}

export { HMAC_BYTES };

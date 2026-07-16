import { hotp, type OtpAlgorithm } from "./hotp.js";
import { totpCounter } from "./totp.js";

export interface VerifyTotpOptions {
  /** Number of time steps to accept on either side of the current one (default 1). */
  window?: number;
  /** Unix time in milliseconds (default: Date.now()). */
  timestamp?: number;
  /** Time step in seconds (default 30). */
  period?: number;
  /** Number of digits in the code (default 6). */
  digits?: number;
  /** HMAC algorithm (default "SHA-1"). */
  algorithm?: OtpAlgorithm;
}

/**
 * Constant-time string comparison.
 *
 * Compares every code point of both strings regardless of where (or whether)
 * they differ, so the running time does not leak the position of the first
 * mismatch. Equal-length inputs (as with fixed-width OTP codes) take the same
 * time for a match and a mismatch.
 */
export function timingSafeEqual(a: string, b: string): boolean {
  const len = Math.max(a.length, b.length);
  let diff = a.length ^ b.length;
  for (let i = 0; i < len; i++) {
    diff |= (a.charCodeAt(i % Math.max(a.length, 1)) || 0) ^ (b.charCodeAt(i % Math.max(b.length, 1)) || 0);
  }
  return diff === 0;
}

/**
 * Verify a user-supplied TOTP code against the shared secret.
 *
 * Accepts codes within `window` time steps before or after the current step,
 * to tolerate client clock drift. Every candidate code is compared with a
 * constant-time comparison.
 *
 * @returns true if the code matches any step in the window.
 */
export async function verifyTotp(
  secret: string,
  code: string,
  opts: VerifyTotpOptions = {},
): Promise<boolean> {
  const { window = 1, timestamp = Date.now(), period = 30, digits = 6, algorithm = "SHA-1" } = opts;
  if (!Number.isInteger(window) || window < 0) {
    throw new RangeError("window must be a non-negative integer");
  }
  if (!Number.isInteger(period) || period <= 0) {
    throw new RangeError("period must be a positive integer number of seconds");
  }

  const counter = totpCounter(timestamp, period);
  let matched = false;
  for (let offset = -window; offset <= window; offset++) {
    const candidate = await hotp(secret, counter + offset, { digits, algorithm });
    if (timingSafeEqual(candidate, code)) {
      matched = true;
    }
  }
  return matched;
}

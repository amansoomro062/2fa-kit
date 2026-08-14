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

export interface VerifyTotpDeltaResult {
  /** Whether the code matched any step in the window. */
  valid: boolean;
  /**
   * Offset of the matched step relative to the current one (0 = current,
   * -1 = previous, 1 = next), or null when the code did not match.
   */
  delta: number | null;
  /**
   * Absolute time step the code matched (counter value), or null when the
   * code did not match. Persist this per user and reject any code whose step
   * is at or below the stored value to prevent replay within the window.
   */
  step: number | null;
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
 * Verify a user-supplied TOTP code and report which time step it matched.
 *
 * Accepts codes within `window` time steps before or after the current one,
 * to tolerate client clock drift. Every candidate in the window is computed
 * and compared with a constant-time comparison, with no early exit.
 *
 * The returned `step` enables replay protection, which RFC 6238 requires:
 * a code must never be accepted twice. Store the accepted step per user
 * (e.g. a `last_used_step` column next to the encrypted secret) and reject
 * any code whose step is not strictly greater:
 *
 * ```ts
 * const result = await verifyTotpWithDelta(secret, code);
 * if (!result.valid || result.step! <= user.lastUsedStep) deny();
 * user.lastUsedStep = result.step!; // persist, then allow
 * ```
 *
 * If the code happens to match more than one step in the window (a 1 in
 * 10^digits coincidence), the earliest matching step is reported.
 */
export async function verifyTotpWithDelta(
  secret: string,
  code: string,
  opts: VerifyTotpOptions = {},
): Promise<VerifyTotpDeltaResult> {
  const { window = 1, timestamp = Date.now(), period = 30, digits = 6, algorithm = "SHA-1" } = opts;
  if (!Number.isInteger(window) || window < 0) {
    throw new RangeError("window must be a non-negative integer");
  }
  if (!Number.isInteger(period) || period <= 0) {
    throw new RangeError("period must be a positive integer number of seconds");
  }

  const counter = totpCounter(timestamp, period);
  let matchedDelta: number | null = null;
  for (let offset = -window; offset <= window; offset++) {
    const candidate = await hotp(secret, counter + offset, { digits, algorithm });
    // no early exit: every candidate is computed and compared
    if (timingSafeEqual(candidate, code) && matchedDelta === null) {
      matchedDelta = offset;
    }
  }
  if (matchedDelta === null) {
    return { valid: false, delta: null, step: null };
  }
  return { valid: true, delta: matchedDelta, step: counter + matchedDelta };
}

/**
 * Verify a user-supplied TOTP code against the shared secret.
 *
 * Accepts codes within `window` time steps before or after the current step,
 * to tolerate client clock drift. Every candidate code is compared with a
 * constant-time comparison.
 *
 * NOTE: a boolean alone cannot prevent replay within the drift window. If an
 * attacker can observe codes in transit, use {@link verifyTotpWithDelta} and
 * persist the accepted step per user.
 *
 * @returns true if the code matches any step in the window.
 */
export async function verifyTotp(
  secret: string,
  code: string,
  opts: VerifyTotpOptions = {},
): Promise<boolean> {
  const { valid } = await verifyTotpWithDelta(secret, code, opts);
  return valid;
}

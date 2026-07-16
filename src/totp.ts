import { hotp, type OtpAlgorithm } from "./hotp.js";

export interface TotpOptions {
  /** Unix time in milliseconds (default: Date.now()). */
  timestamp?: number;
  /** Time step in seconds (default 30). */
  period?: number;
  /** Number of digits in the code (default 6). */
  digits?: number;
  /** HMAC algorithm (default "SHA-1"). */
  algorithm?: OtpAlgorithm;
}

export interface TotpResult {
  /** The current TOTP code. */
  code: string;
  /** Seconds until this code expires. */
  remaining: number;
}

/** Compute the TOTP counter (time step index) for a timestamp. */
export function totpCounter(timestamp: number, period: number): number {
  return Math.floor(timestamp / 1000 / period);
}

/**
 * Generate a TOTP code (RFC 6238).
 *
 * @param secret base32-encoded shared secret (lowercase/padding/spaces tolerated)
 */
export async function totp(secret: string, opts: TotpOptions = {}): Promise<TotpResult> {
  const { timestamp = Date.now(), period = 30, digits = 6, algorithm = "SHA-1" } = opts;
  if (!Number.isInteger(period) || period <= 0) {
    throw new RangeError("period must be a positive integer number of seconds");
  }

  const counter = totpCounter(timestamp, period);
  const code = await hotp(secret, counter, { digits, algorithm });
  const secondsInPeriod = Math.floor(timestamp / 1000) % period;
  return { code, remaining: period - secondsInPeriod };
}

export type { OtpAlgorithm };

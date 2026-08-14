import { describe, expect, it } from "vitest";
import { base32Encode } from "../src/base32.js";
import { totp, totpCounter } from "../src/totp.js";
import { verifyTotp, verifyTotpWithDelta } from "../src/verify.js";

const encoder = new TextEncoder();

// RFC 6238 Appendix B seeds (ASCII), base32-encoded for totp()
const SEED_SHA1 = base32Encode(encoder.encode("12345678901234567890"));
const SEED_SHA256 = base32Encode(encoder.encode("12345678901234567890123456789012"));
const SEED_SHA512 = base32Encode(
  encoder.encode("1234567890123456789012345678901234567890123456789012345678901234"),
);

// RFC 6238 Appendix B vectors: [unixSeconds, SHA1, SHA256, SHA512]
const VECTORS: Array<[number, string, string, string]> = [
  [59, "94287082", "46119246", "90693936"],
  [1111111109, "07081804", "68084774", "25091201"],
  [1111111111, "14050471", "67062674", "99943326"],
  [1234567890, "89005924", "91819424", "93441116"],
  [2000000000, "69279037", "90698825", "38618901"],
  [20000000000, "65353130", "77737706", "47863826"],
];

describe("totp (RFC 6238 Appendix B)", () => {
  for (const [seconds, sha1, sha256, sha512] of VECTORS) {
    const timestamp = seconds * 1000;
    it(`T=${seconds} SHA-1   -> ${sha1}`, async () => {
      const { code } = await totp(SEED_SHA1, { timestamp, digits: 8 });
      expect(code).toBe(sha1);
    });
    it(`T=${seconds} SHA-256 -> ${sha256}`, async () => {
      const { code } = await totp(SEED_SHA256, { timestamp, digits: 8, algorithm: "SHA-256" });
      expect(code).toBe(sha256);
    });
    it(`T=${seconds} SHA-512 -> ${sha512}`, async () => {
      const { code } = await totp(SEED_SHA512, { timestamp, digits: 8, algorithm: "SHA-512" });
      expect(code).toBe(sha512);
    });
  }

  it("reports seconds remaining until the code expires", async () => {
    // T=59 with the default 30s period: counter is 1 (30-59s), 1s remains.
    const { remaining } = await totp(SEED_SHA1, { timestamp: 59_000, digits: 8 });
    expect(remaining).toBe(1);
    // Exactly on a period boundary a full period remains.
    const atBoundary = await totp(SEED_SHA1, { timestamp: 60_000 });
    expect(atBoundary.remaining).toBe(30);
  });

  it("supports custom periods", async () => {
    // Same counter at T=59: 59/60 -> counter 0 vs 59/30 -> counter 1
    const p60 = await totp(SEED_SHA1, { timestamp: 59_000, digits: 8, period: 60 });
    const p30 = await totp(SEED_SHA1, { timestamp: 59_000, digits: 8, period: 30 });
    expect(p60.code).not.toBe(p30.code);
    expect(p60.remaining).toBe(1);
  });
});

describe("verifyTotp", () => {
  const T = 1_700_000_000_000; // arbitrary fixed instant

  it("accepts the current code", async () => {
    const { code } = await totp(SEED_SHA1, { timestamp: T });
    expect(await verifyTotp(SEED_SHA1, code, { timestamp: T })).toBe(true);
  });

  it("rejects a wrong code", async () => {
    expect(await verifyTotp(SEED_SHA1, "000000", { timestamp: T })).toBe(false);
  });

  it("accepts codes within the window", async () => {
    const prev = await totp(SEED_SHA1, { timestamp: T - 30_000 });
    const next = await totp(SEED_SHA1, { timestamp: T + 30_000 });
    expect(await verifyTotp(SEED_SHA1, prev.code, { timestamp: T })).toBe(true);
    expect(await verifyTotp(SEED_SHA1, next.code, { timestamp: T })).toBe(true);
  });

  it("rejects codes outside the window", async () => {
    const twoBack = await totp(SEED_SHA1, { timestamp: T - 60_000 });
    // window 0 only accepts the current step
    expect(await verifyTotp(SEED_SHA1, twoBack.code, { timestamp: T, window: 0 })).toBe(false);
    const prev = await totp(SEED_SHA1, { timestamp: T - 30_000 });
    expect(await verifyTotp(SEED_SHA1, prev.code, { timestamp: T, window: 0 })).toBe(false);
    // wider window accepts it again
    expect(await verifyTotp(SEED_SHA1, twoBack.code, { timestamp: T, window: 2 })).toBe(true);
  });

  it("respects digits and algorithm options", async () => {
    const { code } = await totp(SEED_SHA256, {
      timestamp: T,
      digits: 8,
      algorithm: "SHA-256",
    });
    expect(
      await verifyTotp(SEED_SHA256, code, { timestamp: T, digits: 8, algorithm: "SHA-256" }),
    ).toBe(true);
    // wrong algorithm must not match
    expect(await verifyTotp(SEED_SHA256, code, { timestamp: T, digits: 8 })).toBe(false);
  });

  it("is not fooled by padded or length-mismatched input", async () => {
    const { code } = await totp(SEED_SHA1, { timestamp: T });
    expect(await verifyTotp(SEED_SHA1, `${code}0`, { timestamp: T })).toBe(false);
    expect(await verifyTotp(SEED_SHA1, `0${code.slice(1)}`, { timestamp: T })).toBe(false);
  });
});

describe("verifyTotpWithDelta", () => {
  const T = 1_700_000_000_000; // arbitrary fixed instant
  const STEP = totpCounter(T, 30);

  it("reports delta 0 and the current step for the current code", async () => {
    const { code } = await totp(SEED_SHA1, { timestamp: T });
    const result = await verifyTotpWithDelta(SEED_SHA1, code, { timestamp: T });
    expect(result).toEqual({ valid: true, delta: 0, step: STEP });
  });

  it("reports negative delta for the previous step's code", async () => {
    const prev = await totp(SEED_SHA1, { timestamp: T - 30_000 });
    const result = await verifyTotpWithDelta(SEED_SHA1, prev.code, { timestamp: T });
    expect(result).toEqual({ valid: true, delta: -1, step: STEP - 1 });
  });

  it("reports positive delta for the next step's code", async () => {
    const next = await totp(SEED_SHA1, { timestamp: T + 30_000 });
    const result = await verifyTotpWithDelta(SEED_SHA1, next.code, { timestamp: T });
    expect(result).toEqual({ valid: true, delta: 1, step: STEP + 1 });
  });

  it("returns null delta and step for a wrong code", async () => {
    const result = await verifyTotpWithDelta(SEED_SHA1, "000000", { timestamp: T });
    expect(result).toEqual({ valid: false, delta: null, step: null });
  });

  it("returns null delta and step outside the window", async () => {
    const twoBack = await totp(SEED_SHA1, { timestamp: T - 60_000 });
    const result = await verifyTotpWithDelta(SEED_SHA1, twoBack.code, { timestamp: T });
    expect(result).toEqual({ valid: false, delta: null, step: null });
    const wider = await verifyTotpWithDelta(SEED_SHA1, twoBack.code, { timestamp: T, window: 2 });
    expect(wider).toEqual({ valid: true, delta: -2, step: STEP - 2 });
  });

  it("supports the last-used-step replay pattern", async () => {
    const { code } = await totp(SEED_SHA1, { timestamp: T });
    const first = await verifyTotpWithDelta(SEED_SHA1, code, { timestamp: T });
    expect(first.valid).toBe(true);
    const lastUsedStep = first.step!;
    // The same code presented again resolves to the same step, which the
    // caller must reject as not strictly greater than the stored value.
    const replay = await verifyTotpWithDelta(SEED_SHA1, code, { timestamp: T });
    expect(replay.valid).toBe(true);
    expect(replay.step! <= lastUsedStep).toBe(true);
    // The next step's code passes the same check.
    const next = await totp(SEED_SHA1, { timestamp: T + 30_000 });
    const later = await verifyTotpWithDelta(SEED_SHA1, next.code, { timestamp: T + 30_000 });
    expect(later.valid).toBe(true);
    expect(later.step! > lastUsedStep).toBe(true);
  });

  it("agrees with verifyTotp", async () => {
    const { code } = await totp(SEED_SHA1, { timestamp: T });
    expect(await verifyTotp(SEED_SHA1, code, { timestamp: T })).toBe(true);
    expect((await verifyTotpWithDelta(SEED_SHA1, code, { timestamp: T })).valid).toBe(true);
    expect(await verifyTotp(SEED_SHA1, "999999", { timestamp: T })).toBe(
      (await verifyTotpWithDelta(SEED_SHA1, "999999", { timestamp: T })).valid,
    );
  });
});

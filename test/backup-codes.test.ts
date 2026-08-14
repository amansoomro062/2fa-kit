import { describe, expect, it } from "vitest";
import {
  generateBackupCodes,
  groupCode,
  hmacSha256Hex,
  normalizeBackupCode,
  sha256Hex,
  verifyBackupCode,
} from "../src/backup-codes.js";

describe("generateBackupCodes", () => {
  it("generates 10 codes of 10 characters with digests by default", async () => {
    const { codes, hashed } = await generateBackupCodes();
    expect(codes).toHaveLength(10);
    expect(hashed).toHaveLength(10);
    for (const code of codes) {
      expect(code).toMatch(/^[A-Z2-7]{5}-[A-Z2-7]{5}$/);
    }
    for (const digest of hashed) {
      expect(digest).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it("digests the canonical (ungrouped) form of each code", async () => {
    const { codes, hashed } = await generateBackupCodes({ count: 3 });
    for (let i = 0; i < codes.length; i++) {
      expect(hashed[i]).toBe(await sha256Hex(normalizeBackupCode(codes[i]!)));
    }
  });

  it("uses HMAC-SHA-256 when a key is provided", async () => {
    const { codes, hashed } = await generateBackupCodes({ count: 3, key: "master" });
    for (let i = 0; i < codes.length; i++) {
      const canonical = normalizeBackupCode(codes[i]!);
      expect(hashed[i]).toBe(await hmacSha256Hex("master", canonical));
      expect(hashed[i]).not.toBe(await sha256Hex(canonical));
    }
  });

  it("produces unique codes", async () => {
    const { codes } = await generateBackupCodes({ count: 50 });
    expect(new Set(codes).size).toBe(50);
  });

  it("respects count and length", async () => {
    const { codes } = await generateBackupCodes({ count: 4, length: 12 });
    expect(codes).toHaveLength(4);
    for (const code of codes) {
      // 12 chars grouped by 4 -> "XXXX-XXXX-XXXX"
      expect(code).toMatch(/^([A-Z2-7]{4}-){2}[A-Z2-7]{4}$/);
    }
  });

  it("rejects invalid options", async () => {
    await expect(generateBackupCodes({ count: 0 })).rejects.toThrow(RangeError);
    await expect(generateBackupCodes({ length: 7 })).rejects.toThrow(RangeError);
    await expect(generateBackupCodes({ key: "" })).rejects.toThrow(TypeError);
  });
});

describe("verifyBackupCode", () => {
  it("accepts a code and consumes its digest", async () => {
    const { codes, hashed } = await generateBackupCodes({ count: 3 });
    const { valid, remaining } = await verifyBackupCode(codes[1]!, hashed);
    expect(valid).toBe(true);
    expect(remaining).toHaveLength(2);
    expect(remaining).not.toContain(hashed[1]);
    // the consumed code no longer verifies against the remaining list
    const replay = await verifyBackupCode(codes[1]!, remaining);
    expect(replay.valid).toBe(false);
  });

  it("normalises case, dashes, and whitespace", async () => {
    const { codes, hashed } = await generateBackupCodes({ count: 1 });
    const code = codes[0]!;
    expect((await verifyBackupCode(code.toLowerCase(), hashed)).valid).toBe(true);
    expect((await verifyBackupCode(code.replace(/-/g, ""), hashed)).valid).toBe(true);
    expect((await verifyBackupCode(` ${code.toLowerCase().replace(/-/g, " ")} `, hashed)).valid).toBe(
      true,
    );
  });

  it("rejects wrong codes and leaves the list unchanged", async () => {
    const { hashed } = await generateBackupCodes({ count: 3 });
    const { valid, remaining } = await verifyBackupCode("AAAAA-AAAAA", hashed);
    expect(valid).toBe(false);
    expect(remaining).toEqual(hashed);
  });

  it("requires the same key that was used at generation", async () => {
    const { codes, hashed } = await generateBackupCodes({ count: 2, key: "master" });
    expect((await verifyBackupCode(codes[0]!, hashed, { key: "master" })).valid).toBe(true);
    expect((await verifyBackupCode(codes[0]!, hashed)).valid).toBe(false);
    expect((await verifyBackupCode(codes[0]!, hashed, { key: "wrong" })).valid).toBe(false);
  });

  it("still verifies digests stored by v1.0.x (grouped form, unkeyed)", async () => {
    // v1.0.x generated 8-char codes grouped as XXXX-XXXX and digested the
    // grouped form directly.
    const legacyCode = "AB2C-D3EF";
    const legacyDigest = await sha256Hex(legacyCode);
    const { valid, remaining } = await verifyBackupCode("ab2cd3ef", [legacyDigest]);
    expect(valid).toBe(true);
    expect(remaining).toHaveLength(0);
  });

  it("consumes only one digest when duplicates exist", async () => {
    const { codes, hashed } = await generateBackupCodes({ count: 1 });
    const doubled = [...hashed, ...hashed];
    const { valid, remaining } = await verifyBackupCode(codes[0]!, doubled);
    expect(valid).toBe(true);
    expect(remaining).toHaveLength(1);
  });
});

describe("groupCode", () => {
  it("groups every 4 characters by default", () => {
    expect(groupCode("ABCDEFGH")).toBe("ABCD-EFGH");
    expect(groupCode("ABCDEFGHIJ")).toBe("ABCD-EFGH-IJ");
  });

  it("supports other group sizes", () => {
    expect(groupCode("ABCDEFGHIJ", 5)).toBe("ABCDE-FGHIJ");
  });
});

describe("normalizeBackupCode", () => {
  it("uppercases and strips dashes and whitespace", () => {
    expect(normalizeBackupCode("ab2cd-3efgh")).toBe("AB2CD3EFGH");
    expect(normalizeBackupCode("  AB2CD 3EFGH\t")).toBe("AB2CD3EFGH");
  });
});

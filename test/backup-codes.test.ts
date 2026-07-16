import { describe, expect, it } from "vitest";
import { generateBackupCodes, groupCode, sha256Hex } from "../src/backup-codes.js";

describe("generateBackupCodes", () => {
  it("generates 10 grouped codes with SHA-256 digests by default", async () => {
    const { codes, hashed } = await generateBackupCodes();
    expect(codes).toHaveLength(10);
    expect(hashed).toHaveLength(10);
    for (const code of codes) {
      expect(code).toMatch(/^[A-Z2-7]{4}-[A-Z2-7]{4}$/);
    }
    for (const digest of hashed) {
      expect(digest).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it("digests match the raw codes", async () => {
    const { codes, hashed } = await generateBackupCodes({ count: 3 });
    for (let i = 0; i < codes.length; i++) {
      expect(hashed[i]).toBe(await sha256Hex(codes[i]!));
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
    await expect(generateBackupCodes({ length: 3 })).rejects.toThrow(RangeError);
  });
});

describe("groupCode", () => {
  it("groups every 4 characters", () => {
    expect(groupCode("ABCDEFGH")).toBe("ABCD-EFGH");
    expect(groupCode("ABCDEFGHIJ")).toBe("ABCD-EFGH-IJ");
  });
});

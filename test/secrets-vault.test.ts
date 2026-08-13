import { describe, expect, it } from "vitest";
import {
  createVault,
  decryptSecret,
  deriveKey,
  encryptSecret,
  generateSalt,
} from "../src/secrets-vault.js";

// PBKDF2 iterations are kept low so the suite stays fast; production code
// should use the 210000 default.
const FAST = { iterations: 1000 };

describe("createVault", () => {
  it("round-trips a secret through encrypt and decrypt", async () => {
    const vault = await createVault("master-key-from-env", FAST);
    const { encrypted, salt } = await vault.encrypt("JBSWY3DPEHPK3PXP");
    expect(encrypted).toMatch(/^v1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
    expect(salt).toMatch(/^[0-9a-f]{32}$/);
    expect(await vault.decrypt(encrypted, salt)).toBe("JBSWY3DPEHPK3PXP");
  });

  it("produces a different salt and ciphertext on every encrypt", async () => {
    const vault = await createVault("master-key-from-env", FAST);
    const a = await vault.encrypt("JBSWY3DPEHPK3PXP");
    const b = await vault.encrypt("JBSWY3DPEHPK3PXP");
    expect(a.salt).not.toBe(b.salt);
    expect(a.encrypted).not.toBe(b.encrypted);
    // both still decrypt to the same secret
    expect(await vault.decrypt(a.encrypted, a.salt)).toBe("JBSWY3DPEHPK3PXP");
    expect(await vault.decrypt(b.encrypted, b.salt)).toBe("JBSWY3DPEHPK3PXP");
  });

  it("rejects decryption with the wrong master key", async () => {
    const vault = await createVault("correct-key", FAST);
    const wrong = await createVault("wrong-key", FAST);
    const { encrypted, salt } = await vault.encrypt("JBSWY3DPEHPK3PXP");
    await expect(wrong.decrypt(encrypted, salt)).rejects.toThrow(
      "decryption failed: wrong key or corrupted data",
    );
  });

  it("rejects a tampered ciphertext", async () => {
    const vault = await createVault("master-key-from-env", FAST);
    const { encrypted, salt } = await vault.encrypt("JBSWY3DPEHPK3PXP");
    const parts = encrypted.split(".");
    const ct = parts[2]!;
    const i = ct.length - 1;
    const flipped = ct.slice(0, i) + (ct[i] === "A" ? "B" : "A");
    await expect(vault.decrypt(`${parts[0]}.${parts[1]}.${flipped}`, salt)).rejects.toThrow(
      "decryption failed: wrong key or corrupted data",
    );
  });

  it("rejects malformed payloads", async () => {
    const vault = await createVault("master-key-from-env", FAST);
    const { salt } = await vault.encrypt("JBSWY3DPEHPK3PXP");
    await expect(vault.decrypt("v2.aaaa.bbbb", salt)).rejects.toThrow("malformed payload");
    await expect(vault.decrypt("v1.aaaa", salt)).rejects.toThrow("malformed payload");
    await expect(vault.decrypt("v1.aaaa.bbbb.cccc", salt)).rejects.toThrow("malformed payload");
    await expect(vault.decrypt("not-a-payload", salt)).rejects.toThrow("malformed payload");
    await expect(vault.decrypt("v1.!!!.&&&&", salt)).rejects.toThrow();
  });

  it("rejects an empty master key", async () => {
    await expect(createVault("")).rejects.toThrow(TypeError);
  });
});

describe("deriveKey", () => {
  it("is deterministic: separately derived keys decrypt each other's data", async () => {
    const salt = await generateSalt();
    const key1 = await deriveKey("master-key", salt, FAST);
    const key2 = await deriveKey("master-key", salt, FAST);
    const encrypted = await encryptSecret("JBSWY3DPEHPK3PXP", key1);
    // simulates a restart: re-derive the key from persisted master+salt
    expect(await decryptSecret(encrypted, key2)).toBe("JBSWY3DPEHPK3PXP");
  });

  it("returns non-extractable keys", async () => {
    const key = await deriveKey("master-key", await generateSalt(), FAST);
    expect(key.extractable).toBe(false);
    expect(key.algorithm).toMatchObject({ name: "AES-GCM", length: 256 });
  });

  it("produces different keys for different salts", async () => {
    const salt1 = await generateSalt();
    const salt2 = await generateSalt();
    const key1 = await deriveKey("master-key", salt1, FAST);
    const key2 = await deriveKey("master-key", salt2, FAST);
    const encrypted = await encryptSecret("JBSWY3DPEHPK3PXP", key1);
    await expect(decryptSecret(encrypted, key2)).rejects.toThrow(
      "decryption failed: wrong key or corrupted data",
    );
  });

  it("validates iterations", async () => {
    const salt = await generateSalt();
    await expect(deriveKey("master-key", salt, { iterations: 0 })).rejects.toThrow(RangeError);
    await expect(deriveKey("master-key", salt, { iterations: -5 })).rejects.toThrow(RangeError);
    await expect(deriveKey("master-key", salt, { iterations: 1.5 })).rejects.toThrow(RangeError);
  });

  it("rejects a non-hex salt", async () => {
    await expect(deriveKey("master-key", "not-hex!", FAST)).rejects.toThrow(TypeError);
  });
});

describe("encryptSecret/decryptSecret", () => {
  it("round-trips with a directly derived key", async () => {
    const key = await deriveKey("master-key", await generateSalt(), FAST);
    const encrypted = await encryptSecret("hello world", key);
    expect(await decryptSecret(encrypted, key)).toBe("hello world");
  });

  it("uses a fresh IV per call", async () => {
    const key = await deriveKey("master-key", await generateSalt(), FAST);
    const a = await encryptSecret("same secret", key);
    const b = await encryptSecret("same secret", key);
    expect(a).not.toBe(b);
    expect(a.split(".")[1]).not.toBe(b.split(".")[1]);
  });
});

describe("generateSalt", () => {
  it("returns 32 hex characters by default", async () => {
    const salt = await generateSalt();
    expect(salt).toMatch(/^[0-9a-f]{32}$/);
  });

  it("is unique across many calls", async () => {
    const salts = await Promise.all(Array.from({ length: 100 }, () => generateSalt()));
    expect(new Set(salts).size).toBe(100);
  });

  it("respects a custom byte length", async () => {
    expect(await generateSalt(8)).toMatch(/^[0-9a-f]{16}$/);
    expect(await generateSalt(32)).toMatch(/^[0-9a-f]{64}$/);
  });

  it("validates length", () => {
    expect(() => generateSalt(0)).toThrow(RangeError);
    expect(() => generateSalt(2.5)).toThrow(RangeError);
  });
});

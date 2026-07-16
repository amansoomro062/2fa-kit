import { describe, expect, it } from "vitest";
import { base32Decode, base32Encode } from "../src/base32.js";

const encoder = new TextEncoder();

// RFC 4648 test vectors
const VECTORS: Array<[string, string]> = [
  ["", ""],
  ["f", "MY======"],
  ["fo", "MZXQ===="],
  ["foo", "MZXW6==="],
  ["foob", "MZXW6YQ="],
  ["fooba", "MZXW6YTB"],
  ["foobar", "MZXW6YTBOI======"],
];

describe("base32Encode (RFC 4648)", () => {
  for (const [ascii, base32] of VECTORS) {
    it(`encodes "${ascii}" -> "${base32}"`, () => {
      expect(base32Encode(encoder.encode(ascii))).toBe(base32);
    });
  }
});

describe("base32Decode (RFC 4648)", () => {
  for (const [ascii, base32] of VECTORS) {
    it(`decodes "${base32}" -> "${ascii}"`, () => {
      expect(base32Decode(base32)).toEqual(encoder.encode(ascii));
    });
  }

  it("accepts lowercase input", () => {
    expect(base32Decode("mzxw6ytboi======")).toEqual(encoder.encode("foobar"));
  });

  it("accepts unpadded input", () => {
    expect(base32Decode("MZXW6YTBOI")).toEqual(encoder.encode("foobar"));
  });

  it("ignores spaces", () => {
    expect(base32Decode("MZXW 6YTB OI==")).toEqual(encoder.encode("foobar"));
  });

  it("decodes a 20-byte secret without padding (32 chars)", () => {
    const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    expect(base32Decode(secret)).toEqual(encoder.encode("12345678901234567890"));
  });

  it("throws on invalid characters", () => {
    expect(() => base32Decode("MZXW6!")).toThrow(/Invalid base32/);
  });
});

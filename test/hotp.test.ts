import { describe, expect, it } from "vitest";
import { counterToBytes, hotp } from "../src/hotp.js";

// RFC 4226 Appendix D: secret = ASCII "12345678901234567890"
const SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const EXPECTED = [
  "755224",
  "287082",
  "359152",
  "969429",
  "338314",
  "254676",
  "287922",
  "162583",
  "399871",
  "520489",
];

describe("hotp (RFC 4226 Appendix D)", () => {
  for (let counter = 0; counter < EXPECTED.length; counter++) {
    it(`counter ${counter} -> ${EXPECTED[counter]}`, async () => {
      expect(await hotp(SECRET, counter)).toBe(EXPECTED[counter]);
    });
  }

  it("accepts lowercase and padded secrets", async () => {
    expect(await hotp(SECRET.toLowerCase(), 0)).toBe("755224");
    expect(await hotp("GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ", 0)).toBe("755224");
  });

  it("accepts a bigint counter", async () => {
    expect(await hotp(SECRET, 0n)).toBe("755224");
  });

  it("supports different digit counts", async () => {
    // 7- and 8-digit variants of the first vector
    expect(await hotp(SECRET, 0, { digits: 7 })).toBe("4755224");
    expect(await hotp(SECRET, 0, { digits: 8 })).toBe("84755224");
  });

  it("rejects out-of-range counters", async () => {
    await expect(hotp(SECRET, -1)).rejects.toThrow(RangeError);
    await expect(hotp(SECRET, 1.5)).rejects.toThrow(RangeError);
  });
});

describe("counterToBytes", () => {
  it("serializes small counters big-endian", () => {
    expect([...counterToBytes(1)]).toEqual([0, 0, 0, 0, 0, 0, 0, 1]);
  });

  it("handles counters beyond 32 bits", () => {
    // 0x27BC86AA = 666666666, used by the RFC 6238 T=20000000000 vector
    expect([...counterToBytes(0x27bc86aa)]).toEqual([0, 0, 0, 0, 0x27, 0xbc, 0x86, 0xaa]);
  });
});

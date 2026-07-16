import { describe, expect, it } from "vitest";
import { parseMigrationUri } from "../src/migration.js";
import { base32Encode } from "../src/base32.js";

// --- Tiny protobuf wire-format encoder, used to construct test payloads ---

function varint(value: number | bigint): Uint8Array {
  const bytes: number[] = [];
  let v = BigInt(value);
  do {
    let byte = Number(v & 0x7fn);
    v >>= 7n;
    if (v > 0n) byte |= 0x80;
    bytes.push(byte);
  } while (v > 0n);
  return new Uint8Array(bytes);
}

function key(field: number, wireType: number): Uint8Array {
  return varint((field << 3) | wireType);
}

function lengthDelimited(field: number, data: Uint8Array): Uint8Array {
  return concat(key(field, 2), varint(data.length), data);
}

function varintField(field: number, value: number | bigint): Uint8Array {
  return concat(key(field, 0), varint(value));
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function base64UrlEncode(data: Uint8Array): string {
  let binary = "";
  for (const byte of data) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const encoder = new TextEncoder();

interface TestAccount {
  secret: Uint8Array;
  name: string;
  issuer?: string;
  algorithm?: number; // 1=SHA1 2=SHA256 3=SHA512 4=MD5
  digits?: number; // 1=six 2=eight
  type?: number; // 1=hotp 2=totp
  counter?: number;
}

function encodeOtpParameters(account: TestAccount): Uint8Array {
  const parts: Uint8Array[] = [lengthDelimited(1, account.secret)];
  parts.push(lengthDelimited(2, encoder.encode(account.name)));
  if (account.issuer !== undefined) parts.push(lengthDelimited(3, encoder.encode(account.issuer)));
  if (account.algorithm !== undefined) parts.push(varintField(4, account.algorithm));
  if (account.digits !== undefined) parts.push(varintField(5, account.digits));
  if (account.type !== undefined) parts.push(varintField(6, account.type));
  if (account.counter !== undefined) parts.push(varintField(7, account.counter));
  return concat(...parts);
}

function buildMigrationUri(accounts: TestAccount[]): string {
  const payloadParts = accounts.map((a) => lengthDelimited(1, encodeOtpParameters(a)));
  // batch metadata (version=1, batch_size=1, batch_index=0, batch_id=12345)
  payloadParts.push(varintField(2, 1), varintField(3, 1), varintField(4, 0), varintField(5, 12345));
  const payload = concat(...payloadParts);
  return `otpauth-migration://offline?data=${base64UrlEncode(payload)}`;
}

describe("parseMigrationUri", () => {
  it("round-trips multiple accounts", async () => {
    const secretA = encoder.encode("12345678901234567890");
    const secretB = encoder.encode("another-secret");
    const uri = buildMigrationUri([
      {
        secret: secretA,
        name: "Acme:alice@example.com",
        issuer: "Acme",
        algorithm: 1,
        digits: 1,
        type: 2,
      },
      { secret: secretB, name: "bob@example.com", algorithm: 2, digits: 2, type: 2 },
    ]);

    const accounts = await parseMigrationUri(uri);
    expect(accounts).toEqual([
      {
        type: "totp",
        label: "Acme:alice@example.com",
        issuer: "Acme",
        secret: base32Encode(secretA),
        algorithm: "SHA1",
        digits: 6,
      },
      {
        type: "totp",
        label: "bob@example.com",
        secret: base32Encode(secretB),
        algorithm: "SHA256",
        digits: 8,
      },
    ]);
  });

  it("maps hotp accounts and their counters", async () => {
    const secret = encoder.encode("12345678901234567890");
    const uri = buildMigrationUri([
      { secret, name: "legacy", algorithm: 3, digits: 1, type: 1, counter: 12345678901 },
    ]);
    const [account] = await parseMigrationUri(uri);
    expect(account).toEqual({
      type: "hotp",
      label: "legacy",
      secret: base32Encode(secret),
      algorithm: "SHA512",
      digits: 6,
      counter: 12345678901,
    });
  });

  it("omits unspecified enum values", async () => {
    const secret = encoder.encode("12345678901234567890");
    // type=0 (unspecified) and algorithm=0 are Google Authenticator's defaults
    const uri = buildMigrationUri([{ secret, name: "defaults" }]);
    const [account] = await parseMigrationUri(uri);
    expect(account).toEqual({
      type: "totp",
      label: "defaults",
      secret: base32Encode(secret),
    });
  });

  it("skips accounts without a secret", async () => {
    const secret = encoder.encode("12345678901234567890");
    const empty = new Uint8Array(0);
    const uri = buildMigrationUri([
      { secret: empty, name: "broken" },
      { secret, name: "ok" },
    ]);
    const accounts = await parseMigrationUri(uri);
    expect(accounts).toHaveLength(1);
    expect(accounts[0]!.label).toBe("ok");
  });

  it("rejects malformed input", async () => {
    await expect(parseMigrationUri("not a uri")).rejects.toThrow(TypeError);
    await expect(parseMigrationUri("otpauth://totp/x?secret=ABC")).rejects.toThrow(TypeError);
    await expect(parseMigrationUri("otpauth-migration://offline")).rejects.toThrow(TypeError);
    // valid base64url, but truncated protobuf (varint field without enough bytes)
    await expect(
      parseMigrationUri("otpauth-migration://offline?data=" + base64UrlEncode(new Uint8Array([0x0a, 0xff]))),
    ).rejects.toThrow();
  });
});

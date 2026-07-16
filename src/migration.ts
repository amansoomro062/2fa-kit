/**
 * Google Authenticator migration import.
 *
 * Parses otpauth-migration://offline?data=<base64url> URIs produced by
 * Google Authenticator's "Transfer accounts" feature. The payload is a
 * protobuf message; the minimal wire-format reader below is hand-rolled to
 * keep this package dependency-free.
 *
 * Schema (google-authenticator-android, migration_payload.proto):
 *
 *   message MigrationPayload {
 *     repeated OtpParameters otp_parameters = 1;
 *     int32 version = 2;
 *     int32 batch_size = 3;
 *     int32 batch_index = 4;
 *     int64 batch_id = 5;
 *   }
 *   message OtpParameters {
 *     bytes secret = 1;
 *     string name = 2;
 *     string issuer = 3;
 *     Algorithm algorithm = 4;   // 0=unspecified 1=SHA1 2=SHA256 3=SHA512 4=MD5
 *     int32 digits = 5;          // 0=unspecified 1=six 2=eight
 *     OtpType type = 6;          // 0=unspecified 1=hotp 2=totp
 *     int64 counter = 7;
 *   }
 */

import { base32Encode } from "./base32.js";
import type { ParsedOtpauth } from "./uri.js";

const WIRE_VARINT = 0;
const WIRE_64BIT = 1;
const WIRE_LENGTH_DELIMITED = 2;
const WIRE_32BIT = 5;

interface OtpParameters {
  secret: Uint8Array | null;
  name: string;
  issuer: string;
  algorithm: number;
  digits: number;
  type: number;
  counter: bigint;
}

class ProtobufReader {
  private pos = 0;

  constructor(private readonly data: Uint8Array) {}

  get done(): boolean {
    return this.pos >= this.data.length;
  }

  readVarint(): bigint {
    let result = 0n;
    let shift = 0n;
    for (;;) {
      if (this.pos >= this.data.length) {
        throw new Error("Truncated protobuf varint");
      }
      const byte = this.data[this.pos++]!;
      result |= BigInt(byte & 0x7f) << shift;
      if ((byte & 0x80) === 0) {
        return result;
      }
      shift += 7n;
      if (shift > 70n) {
        throw new Error("Protobuf varint too long");
      }
    }
  }

  /** Read a field key; returns [fieldNumber, wireType]. */
  readKey(): [number, number] {
    const key = this.readVarint();
    return [Number(key >> 3n), Number(key & 0x7n)];
  }

  readBytes(): Uint8Array {
    const length = Number(this.readVarint());
    if (length < 0 || this.pos + length > this.data.length) {
      throw new Error("Truncated protobuf length-delimited field");
    }
    const slice = this.data.subarray(this.pos, this.pos + length);
    this.pos += length;
    return slice;
  }

  /** Skip a field of the given wire type. */
  skip(wireType: number): void {
    switch (wireType) {
      case WIRE_VARINT:
        this.readVarint();
        return;
      case WIRE_64BIT:
        this.advance(8);
        return;
      case WIRE_LENGTH_DELIMITED:
        this.readBytes();
        return;
      case WIRE_32BIT:
        this.advance(4);
        return;
      default:
        throw new Error(`Unsupported protobuf wire type: ${wireType}`);
    }
  }

  private advance(n: number): void {
    if (this.pos + n > this.data.length) {
      throw new Error("Truncated protobuf field");
    }
    this.pos += n;
  }
}

function base64UrlDecode(input: string): Uint8Array {
  if (typeof atob !== "function") {
    throw new Error("atob is not available in this runtime");
  }
  const base64 = input.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

const decoder = new TextDecoder();

function parseOtpParameters(data: Uint8Array): OtpParameters {
  const reader = new ProtobufReader(data);
  const params: OtpParameters = {
    secret: null,
    name: "",
    issuer: "",
    algorithm: 0,
    digits: 0,
    type: 0,
    counter: 0n,
  };
  while (!reader.done) {
    const [field, wire] = reader.readKey();
    switch (field) {
      case 1:
        params.secret = new Uint8Array(reader.readBytes());
        break;
      case 2:
        params.name = decoder.decode(reader.readBytes());
        break;
      case 3:
        params.issuer = decoder.decode(reader.readBytes());
        break;
      case 4:
        params.algorithm = Number(reader.readVarint());
        break;
      case 5:
        params.digits = Number(reader.readVarint());
        break;
      case 6:
        params.type = Number(reader.readVarint());
        break;
      case 7:
        params.counter = reader.readVarint();
        break;
      default:
        reader.skip(wire);
    }
  }
  return params;
}

function mapAlgorithm(value: number): string | undefined {
  switch (value) {
    case 1:
      return "SHA1";
    case 2:
      return "SHA256";
    case 3:
      return "SHA512";
    case 4:
      return "MD5";
    default:
      return undefined;
  }
}

function mapDigits(value: number): number | undefined {
  switch (value) {
    case 1:
      return 6;
    case 2:
      return 8;
    default:
      return undefined;
  }
}

/**
 * Parse a Google Authenticator migration URI
 * (otpauth-migration://offline?data=...) into one ParsedOtpauth per account.
 */
export async function parseMigrationUri(uri: string): Promise<ParsedOtpauth[]> {
  let url: URL;
  try {
    url = new URL(uri);
  } catch {
    throw new TypeError(`Invalid otpauth-migration URI: ${uri}`);
  }
  if (url.protocol !== "otpauth-migration:") {
    throw new TypeError(`Expected otpauth-migration: protocol, got ${url.protocol}`);
  }
  const data = url.searchParams.get("data");
  if (!data) {
    throw new TypeError("otpauth-migration URI is missing the data parameter");
  }

  const payload = base64UrlDecode(data);
  const reader = new ProtobufReader(payload);
  const accounts: ParsedOtpauth[] = [];

  while (!reader.done) {
    const [field, wire] = reader.readKey();
    if (field === 1 && wire === WIRE_LENGTH_DELIMITED) {
      const params = parseOtpParameters(reader.readBytes());
      if (!params.secret || params.secret.length === 0) {
        continue; // skip entries without a secret
      }
      const type = params.type === 1 ? "hotp" : "totp"; // 0/2 both treated as totp
      const parsed: ParsedOtpauth = {
        type,
        label: params.name,
        secret: base32Encode(params.secret),
      };
      if (params.issuer) parsed.issuer = params.issuer;
      const algorithm = mapAlgorithm(params.algorithm);
      if (algorithm) parsed.algorithm = algorithm;
      const digits = mapDigits(params.digits);
      if (digits !== undefined) parsed.digits = digits;
      if (type === "hotp") parsed.counter = Number(params.counter);
      accounts.push(parsed);
    } else {
      reader.skip(wire);
    }
  }

  return accounts;
}

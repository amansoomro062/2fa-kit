/**
 * RFC 4648 base32 encode/decode (no external dependencies).
 *
 * Decoding is liberal on purpose: it accepts lowercase input and ignores
 * padding (`=`) and whitespace, because secrets copied out of authenticator
 * apps often arrive in that shape.
 */

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

const DECODE_TABLE: Int16Array = (() => {
  const table = new Int16Array(128).fill(-1);
  for (let i = 0; i < ALPHABET.length; i++) {
    const upper = ALPHABET.charCodeAt(i);
    table[upper] = i;
    // lowercase letters map to the same values
    if (upper >= 65 && upper <= 90) {
      table[upper + 32] = i;
    }
  }
  return table;
})();

/** Encode bytes as RFC 4648 base32 (uppercase, with `=` padding). */
export function base32Encode(data: Uint8Array): string {
  let output = "";
  let buffer = 0;
  let bitsLeft = 0;
  for (const byte of data) {
    buffer = (buffer << 8) | byte;
    bitsLeft += 8;
    while (bitsLeft >= 5) {
      bitsLeft -= 5;
      output += ALPHABET[(buffer >> bitsLeft) & 0x1f];
    }
  }
  if (bitsLeft > 0) {
    output += ALPHABET[(buffer << (5 - bitsLeft)) & 0x1f];
  }
  while (output.length % 8 !== 0) {
    output += "=";
  }
  return output;
}

/**
 * Decode a base32 string to bytes.
 *
 * Accepts uppercase or lowercase; ignores `=` padding, spaces and other
 * ASCII whitespace. Throws on any other invalid character.
 */
export function base32Decode(input: string): Uint8Array {
  const bytes: number[] = [];
  let buffer = 0;
  let bitsLeft = 0;
  for (let i = 0; i < input.length; i++) {
    const code = input.charCodeAt(i);
    if (code === 0x3d /* = */ || code === 0x20 /* space */ || code === 0x09 || code === 0x0a || code === 0x0d) {
      continue;
    }
    const value = code < 128 ? DECODE_TABLE[code]! : -1;
    if (value < 0) {
      throw new Error(`Invalid base32 character at index ${i}`);
    }
    buffer = (buffer << 5) | value;
    bitsLeft += 5;
    if (bitsLeft >= 8) {
      bitsLeft -= 8;
      bytes.push((buffer >> bitsLeft) & 0xff);
    }
  }
  return new Uint8Array(bytes);
}

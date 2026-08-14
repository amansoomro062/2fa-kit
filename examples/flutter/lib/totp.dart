// Hand-rolled TOTP (RFC 6238) / HOTP (RFC 4226) for Dart.
//
// 2fa-kit is TypeScript and cannot run inside a Flutter app, so this file
// reimplements the same standard natively. Codes produced here are identical
// to codes produced by 2fa-kit (and Google Authenticator) for the same
// secret, algorithm, digits, and period.

import 'dart:typed_data';

import 'package:crypto/crypto.dart';

/// HMAC algorithm used for the OTP. Defaults to SHA-1, like the rest of the
/// authenticator ecosystem (and 2fa-kit).
enum OtpAlgorithm { sha1, sha256, sha512 }

Hash _hashFor(OtpAlgorithm algorithm) {
  switch (algorithm) {
    case OtpAlgorithm.sha1:
      return sha1;
    case OtpAlgorithm.sha256:
      return sha256;
    case OtpAlgorithm.sha512:
      return sha512;
  }
}

/// Decode an RFC 4648 base32 string. Tolerates lowercase, whitespace, and
/// padding, the same way 2fa-kit and the authenticator apps accept secrets.
Uint8List base32Decode(String input) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  final cleaned = input.toUpperCase().replaceAll(RegExp(r'[\s=]'), '');
  if (cleaned.isEmpty) {
    throw const FormatException('Empty base32 input');
  }
  var buffer = 0;
  var bitsLeft = 0;
  final out = <int>[];
  for (final unit in cleaned.codeUnits) {
    final value = alphabet.indexOf(String.fromCharCode(unit));
    if (value < 0) {
      throw FormatException('Invalid base32 character: ${String.fromCharCode(unit)}');
    }
    buffer = (buffer << 5) | value;
    bitsLeft += 5;
    if (bitsLeft >= 8) {
      bitsLeft -= 8;
      out.add((buffer >> bitsLeft) & 0xFF);
      // Keep only the bits not yet consumed so the buffer stays small and
      // correct on platforms where int arithmetic is limited (web).
      buffer &= (1 << bitsLeft) - 1;
    }
  }
  return Uint8List.fromList(out);
}

/// Generate an HOTP code (RFC 4226) for [counter].
String hotp(
  List<int> key,
  int counter, {
  int digits = 6,
  OtpAlgorithm algorithm = OtpAlgorithm.sha1,
}) {
  if (counter < 0) {
    throw ArgumentError.value(counter, 'counter', 'must be >= 0');
  }
  // 8-byte big-endian counter. Division is used instead of bit shifts so
  // values above 32 bits stay correct everywhere, including the web where
  // bitwise ops truncate to 32 bits.
  final bytes = Uint8List(8);
  final data = ByteData.view(bytes.buffer);
  data.setUint32(0, counter ~/ 0x100000000);
  data.setUint32(4, counter % 0x100000000);

  final digest = Hmac(_hashFor(algorithm), key).convert(bytes).bytes;

  // Dynamic truncation (RFC 4226 section 5.3).
  final offset = digest[digest.length - 1] & 0x0F;
  final binary = ((digest[offset] & 0x7F) << 24) |
      (digest[offset + 1] << 16) |
      (digest[offset + 2] << 8) |
      digest[offset + 3];

  final mod = _pow10(digits);
  return (binary % mod).toString().padLeft(digits, '0');
}

/// Generate a TOTP code (RFC 6238). [time] is seconds since the Unix epoch;
/// omit it to use the current time.
String totp(
  List<int> key, {
  int? time,
  int period = 30,
  int digits = 6,
  OtpAlgorithm algorithm = OtpAlgorithm.sha1,
}) {
  final t = time ?? DateTime.now().millisecondsSinceEpoch ~/ 1000;
  return hotp(key, t ~/ period, digits: digits, algorithm: algorithm);
}

/// Seconds until the current TOTP code expires.
int remainingSeconds({int period = 30, int? time}) {
  final t = time ?? DateTime.now().millisecondsSinceEpoch ~/ 1000;
  return period - (t % period);
}

int _pow10(int digits) {
  var result = 1;
  for (var i = 0; i < digits; i++) {
    result *= 10;
  }
  return result;
}

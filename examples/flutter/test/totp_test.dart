// RFC 6238 conformance tests for the hand-rolled TOTP implementation.
//
// Test vectors from RFC 6238 Appendix B, SHA-1, 8 digits. The shared secret
// is the ASCII string "12345678901234567890", base32-encoded.

import 'package:flutter_test/flutter_test.dart';
import 'package:whitelabel_authenticator/totp.dart';

void main() {
  // ASCII "12345678901234567890" -> base32.
  const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

  test('base32Decode decodes the RFC 6238 test secret', () {
    expect(String.fromCharCodes(base32Decode(secret)), '12345678901234567890');
  });

  test('base32Decode tolerates lowercase, spaces, and padding', () {
    expect(
      base32Decode('gezd gnbv gy3t qojq gezdgnbvgy3tqojq=='),
      base32Decode(secret),
    );
  });

  test('base32Decode rejects invalid characters', () {
    expect(() => base32Decode('GEZDGNBV!'), throwsFormatException);
  });

  group('RFC 6238 Appendix B, SHA-1, 8 digits', () {
    final key = base32Decode(secret);

    test('T = 59 -> 94287082', () {
      expect(totp(key, time: 59, digits: 8), '94287082');
    });

    test('T = 1111111109 -> 07081804', () {
      expect(totp(key, time: 1111111109, digits: 8), '07081804');
    });

    test('T = 1234567890 -> 89005924', () {
      expect(totp(key, time: 1234567890, digits: 8), '89005924');
    });
  });

  test('defaults to 6 digits and a 30-second period', () {
    final key = base32Decode(secret);
    final code = totp(key, time: 59);
    expect(code.length, 6);
    // Same instant, 6 digits: last 6 of the 8-digit code.
    expect(code, '287082');
  });

  test('remainingSeconds counts down within the period', () {
    expect(remainingSeconds(period: 30, time: 0), 30);
    expect(remainingSeconds(period: 30, time: 59), 1);
    expect(remainingSeconds(period: 30, time: 60), 30);
  });

  test('hotp supports counters above 32 bits', () {
    // Regression guard for the big-endian counter encoding: values above
    // 2^32 must not wrap or truncate. Expected value computed independently
    // with Node.js crypto (same key, counter = 2^32, SHA-1, 8 digits).
    final key = base32Decode(secret);
    expect(hotp(key, 0x100000000, digits: 8), '55999456');
  });
}

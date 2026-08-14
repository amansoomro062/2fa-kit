// Parser for otpauth:// URIs, the format behind authenticator QR codes.
// Mirrors what 2fa-kit's parseUri produces: type, label, issuer, secret,
// and optional algorithm / digits / period / counter parameters.

import 'totp.dart';

class OtpAccount {
  OtpAccount({
    required this.type,
    required this.label,
    required this.secret,
    this.issuer,
    this.algorithm = OtpAlgorithm.sha1,
    this.digits = 6,
    this.period = 30,
    this.counter,
  });

  /// 'totp' or 'hotp'.
  final String type;

  /// Account name shown to the user, e.g. "alice@example.com".
  final String label;

  /// Issuer name, e.g. "Acme". Falls back to the "Issuer:" prefix embedded
  /// in the label when the query parameter is absent.
  final String? issuer;

  /// Base32 shared secret, kept as entered.
  final String secret;

  final OtpAlgorithm algorithm;
  final int digits;
  final int period;

  /// Only meaningful for HOTP accounts.
  final int? counter;

  Map<String, dynamic> toJson() => {
        'type': type,
        'label': label,
        'issuer': issuer,
        'secret': secret,
        'algorithm': algorithm.name,
        'digits': digits,
        'period': period,
        'counter': counter,
      };

  factory OtpAccount.fromJson(Map<String, dynamic> json) => OtpAccount(
        type: json['type'] as String? ?? 'totp',
        label: json['label'] as String? ?? '',
        issuer: json['issuer'] as String?,
        secret: json['secret'] as String? ?? '',
        algorithm: OtpAlgorithm.values.asNameMap()[json['algorithm']] ??
            OtpAlgorithm.sha1,
        digits: json['digits'] as int? ?? 6,
        period: json['period'] as int? ?? 30,
        counter: json['counter'] as int?,
      );
}

/// Parse an `otpauth://` URI into an [OtpAccount].
///
/// Throws [FormatException] on anything malformed: wrong scheme, missing
/// secret, unknown algorithm, non-numeric digits/period.
OtpAccount parseOtpauthUri(String uriString) {
  final Uri uri;
  try {
    uri = Uri.parse(uriString.trim());
  } on FormatException {
    throw const FormatException('Not a valid URI');
  }
  if (uri.scheme != 'otpauth') {
    throw FormatException('Expected an otpauth:// URI, got scheme "${uri.scheme}"');
  }
  final type = uri.host.toLowerCase();
  if (type != 'totp' && type != 'hotp') {
    throw FormatException('Unsupported OTP type "${uri.host}" (expected totp or hotp)');
  }

  // pathSegments are already percent-decoded. The label may carry an
  // "Issuer:account" prefix.
  var label = uri.pathSegments.isNotEmpty ? uri.pathSegments.first : '';
  String? labelIssuer;
  final colon = label.indexOf(':');
  if (colon > 0) {
    labelIssuer = label.substring(0, colon);
    label = label.substring(colon + 1).trim();
  }

  final params = uri.queryParameters;
  final secret = params['secret'];
  if (secret == null || secret.trim().isEmpty) {
    throw const FormatException('URI is missing the "secret" parameter');
  }

  final algorithm = _parseAlgorithm(params['algorithm']);
  final digits = _parseInt(params['digits'], 6, 'digits');
  final period = _parseInt(params['period'], 30, 'period');
  if (digits < 6 || digits > 8) {
    throw FormatException('digits must be between 6 and 8, got $digits');
  }
  if (period <= 0) {
    throw FormatException('period must be positive, got $period');
  }
  final counter = params['counter'] == null
      ? null
      : _parseInt(params['counter'], 0, 'counter');

  return OtpAccount(
    type: type,
    label: label.isEmpty ? '(unnamed account)' : label,
    issuer: params['issuer'] ?? labelIssuer,
    secret: secret.trim(),
    algorithm: algorithm,
    digits: digits,
    period: period,
    counter: counter,
  );
}

OtpAlgorithm _parseAlgorithm(String? value) {
  switch ((value ?? 'SHA1').toUpperCase()) {
    case 'SHA1':
      return OtpAlgorithm.sha1;
    case 'SHA256':
      return OtpAlgorithm.sha256;
    case 'SHA512':
      return OtpAlgorithm.sha512;
    default:
      throw FormatException('Unsupported algorithm "$value"');
  }
}

int _parseInt(String? value, int fallback, String name) {
  if (value == null) return fallback;
  final parsed = int.tryParse(value);
  if (parsed == null) {
    throw FormatException('Parameter "$name" is not a number: "$value"');
  }
  return parsed;
}

import Foundation

/// HMAC algorithm for HOTP/TOTP. SHA-1 is the ecosystem default and matches
/// 2fa-kit's default; SHA-256 and SHA-512 are supported via the otpauth URI
/// "algorithm" parameter.
enum OtpAlgorithm: String, Codable, CaseIterable {
    case sha1 = "SHA1"
    case sha256 = "SHA256"
    case sha512 = "SHA512"
}

/// One enrolled account. Secrets are persisted in the iOS Keychain as part
/// of the encoded account list (see AccountStore).
struct Account: Identifiable, Codable, Equatable {
    var id: UUID = UUID()
    /// Display label, e.g. the user's email ("alice@example.com").
    var label: String
    /// Service name, e.g. "Acme".
    var issuer: String
    /// Base32-encoded shared secret, uppercase, no padding.
    var secret: String
    var algorithm: OtpAlgorithm = .sha1
    var digits: Int = 6
    var period: Int = 30

    /// Decoded secret bytes + parameters, ready for Totp.code().
    /// Returns nil if the secret is not valid base32.
    var totpParameters: TotpParameters? {
        guard let key = Base32.decode(secret) else { return nil }
        return TotpParameters(secret: key, algorithm: algorithm, digits: digits, period: period)
    }
}

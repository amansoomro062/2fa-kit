import Foundation
import CryptoKit

// Hand-rolled TOTP (RFC 6238) / HOTP (RFC 4226) core.
//
// 2fa-kit is TypeScript and cannot run inside a native iOS app, so this file
// reimplements the same standard natively using CryptoKit. Codes generated
// here are identical to 2fa-kit's totp()/hotp() output for the same secret,
// algorithm, digits, period, and counter.

/// Parameters for one HOTP/TOTP computation.
struct TotpParameters {
    var secret: Data
    var algorithm: OtpAlgorithm = .sha1
    var digits: Int = 6
    var period: Int = 30
}

enum Totp {
    /// Current TOTP code and the seconds left in the current time step.
    /// This mirrors 2fa-kit's totp(secret, opts?) -> { code, remaining }.
    static func code(for params: TotpParameters, at date: Date = Date()) -> (code: String, remaining: Int) {
        let seconds = Int64(date.timeIntervalSince1970)
        let period = Int64(max(params.period, 1))
        let counter = UInt64(seconds / period)
        let code = hotp(params, counter: counter)
        let remaining = Int(period - (seconds % period))
        return (code, remaining)
    }

    /// RFC 4226 HOTP: HMAC over an 8-byte big-endian counter, then dynamic
    /// truncation. Using UInt64 keeps counters above 2^32 correct.
    static func hotp(_ params: TotpParameters, counter: UInt64) -> String {
        var bigEndianCounter = counter.bigEndian
        let message = Data(bytes: &bigEndianCounter, count: 8)
        let digest = hmac(params.algorithm, key: params.secret, message: message)

        // Dynamic truncation (RFC 4226 section 5.3).
        let offset = Int(digest[digest.count - 1] & 0x0F)
        let binary = (UInt32(digest[offset]) & 0x7F) << 24
            | UInt32(digest[offset + 1]) << 16
            | UInt32(digest[offset + 2]) << 8
            | UInt32(digest[offset + 3])

        let digits = min(max(params.digits, 6), 8)
        let modulus = UInt32(pow(10.0, Double(digits)))
        let otp = binary % modulus
        return String(format: "%0\(digits)u", otp)
    }

    /// HMAC via CryptoKit. SHA-1 is the authenticator-ecosystem default;
    /// Insecure.SHA1 is only "insecure" for collision resistance, which does
    /// not apply to HMAC (RFC 2104), and is what every authenticator app uses.
    private static func hmac(_ algorithm: OtpAlgorithm, key: Data, message: Data) -> Data {
        let symmetricKey = SymmetricKey(data: key)
        switch algorithm {
        case .sha1:
            return Data(HMAC<Insecure.SHA1>.authenticationCode(for: message, key: symmetricKey))
        case .sha256:
            return Data(HMAC<SHA256>.authenticationCode(for: message, key: symmetricKey))
        case .sha512:
            return Data(HMAC<SHA512>.authenticationCode(for: message, key: symmetricKey))
        }
    }
}

/// RFC 4648 base32 decoding, tolerant of the formats authenticator apps and
/// servers actually emit: lowercase, missing padding, embedded spaces.
/// This matches 2fa-kit's base32Decode() acceptance rules.
enum Base32 {
    private static let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".utf8)

    static func decode(_ string: String) -> Data? {
        // Build a reverse lookup table. Lowercase letters map to the same
        // values as uppercase. Only A-Z get a lowercase alias: adding 32 to
        // the digit characters '2'-'7' would clobber the letters 'R'-'W'.
        var table = [UInt8](repeating: 0xFF, count: 128)
        for (index, char) in alphabet.enumerated() {
            table[Int(char)] = UInt8(index)
            if char >= 65 && char <= 90 { // 'A'...'Z'
                table[Int(char + 32)] = UInt8(index) // 'A' + 32 == 'a' in ASCII
            }
        }

        var buffer: UInt64 = 0
        var bits = 0
        var output = Data()

        for scalar in string.unicodeScalars {
            let value = scalar.value
            // Skip '=' padding and ASCII whitespace, like 2fa-kit's
            // base32Decode; also tolerate '-' used as a grouping separator.
            if value == 0x3D || value == 0x20 || value == 0x09 || value == 0x0A
                || value == 0x0D || scalar == "-" {
                continue
            }
            guard value < 128, table[Int(value)] != 0xFF else { return nil }
            buffer = (buffer << 5) | UInt64(table[Int(value)])
            bits += 5
            if bits >= 8 {
                bits -= 8
                output.append(UInt8((buffer >> UInt64(bits)) & 0xFF))
                buffer &= (1 << UInt64(bits)) - 1 // keep only the unflushed bits
            }
        }
        return output
    }
}

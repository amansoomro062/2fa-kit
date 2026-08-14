import Foundation

enum OtpauthParseError: LocalizedError {
    case notOtpauth
    case unsupportedType(String)
    case missingSecret
    case invalidSecret

    var errorDescription: String? {
        switch self {
        case .notOtpauth:
            return "Not an otpauth:// URI."
        case .unsupportedType(let type):
            return "Unsupported type \"\(type)\". Only totp is supported."
        case .missingSecret:
            return "The URI has no secret parameter."
        case .invalidSecret:
            return "The secret is not valid base32."
        }
    }
}

/// Parses otpauth:// URIs, accepting the same parameters 2fa-kit's
/// buildUri()/parseUri() produce: secret, issuer, algorithm, digits, period.
enum OtpauthParser {
    static func parse(_ uriString: String) -> Result<Account, OtpauthParseError> {
        let trimmed = uriString.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.lowercased().hasPrefix("otpauth://"),
              let components = URLComponents(string: trimmed),
              let host = components.host else {
            return .failure(.notOtpauth)
        }
        guard host.lowercased() == "totp" else {
            return .failure(.unsupportedType(host))
        }

        let query = Dictionary(
            uniqueKeysWithValues: (components.queryItems ?? []).compactMap { item in
                item.value.map { (item.name.lowercased(), $0) }
            }
        )

        guard let rawSecret = query["secret"], !rawSecret.isEmpty else {
            return .failure(.missingSecret)
        }
        // Normalize the way 2fa-kit does: uppercase, no spaces or padding.
        let secret = rawSecret.uppercased()
            .replacingOccurrences(of: " ", with: "")
            .replacingOccurrences(of: "=", with: "")
        guard Base32.decode(secret) != nil else {
            return .failure(.invalidSecret)
        }

        // The path is "/Issuer:label" (issuer prefix optional).
        let path = String(components.path.dropFirst())
            .removingPercentEncoding ?? String(components.path.dropFirst())
        let parts = path.split(separator: ":", maxSplits: 1).map(String.init)
        let pathIssuer = parts.count == 2 ? parts[0] : nil
        let label = parts.count == 2 ? parts[1] : (parts.first ?? "")

        let algorithm = OtpAlgorithm(rawValue: (query["algorithm"] ?? "SHA1").uppercased()) ?? .sha1
        let digits = min(max(Int(query["digits"] ?? "") ?? 6, 6), 8)
        let period = max(Int(query["period"] ?? "") ?? 30, 1)

        return .success(Account(
            label: label.isEmpty ? "Account" : label,
            issuer: query["issuer"] ?? pathIssuer ?? "",
            secret: secret,
            algorithm: algorithm,
            digits: digits,
            period: period
        ))
    }
}

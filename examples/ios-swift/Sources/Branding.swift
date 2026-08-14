import SwiftUI

// White-label configuration.
//
// This file mirrors branding.json at the example root. To rebrand the app,
// edit BOTH of them (plus the app icon in Sources/Assets.xcassets) and
// update PRODUCT_BUNDLE_IDENTIFIER in project.yml:
//   - branding.json: single source of truth for build tooling and docs
//   - Branding.swift (this file): the values actually compiled into the app
enum Branding {
    static let appName = "Acme Authenticator"
    static let issuer = "Acme"
    static let bundleIdSuffix = "authenticator"
    static let primaryColor = Color(hex: "#1D4ED8")
    static let accentColor = Color(hex: "#F59E0B")
    /// Path of the app-icon set inside the asset catalog, for reference.
    static let logoPath = "Sources/Assets.xcassets/AppIcon.appiconset"
}

extension Color {
    /// Create a color from a "#RRGGBB" hex string.
    init(hex: String) {
        var s = hex.trimmingCharacters(in: .whitespacesAndNewlines)
        if s.hasPrefix("#") { s.removeFirst() }
        var value: UInt64 = 0
        Scanner(string: s).scanHexInt64(&value)
        if s.count == 6 {
            self.init(
                red: Double((value >> 16) & 0xFF) / 255,
                green: Double((value >> 8) & 0xFF) / 255,
                blue: Double(value & 0xFF) / 255
            )
        } else {
            self.init(red: 0, green: 0, blue: 0)
        }
    }
}

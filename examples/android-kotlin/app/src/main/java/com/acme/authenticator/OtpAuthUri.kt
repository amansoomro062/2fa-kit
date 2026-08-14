package com.acme.authenticator

import android.net.Uri

/** One stored account, parsed from an otpauth:// URI. */
data class Account(
    val label: String,
    val issuer: String,
    val secret: String,
    val algorithm: String = "SHA1",
    val digits: Int = 6,
    val period: Int = 30,
) {
    val totpParams: Totp.Params
        get() = Totp.Params(algorithm = algorithm, digits = digits, period = period)
}

/**
 * Parses otpauth://totp/ URIs, the same format 2fa-kit's buildUri produces
 * and parseUri consumes. HOTP URIs are rejected: this app displays live
 * time-based codes only.
 */
object OtpAuthUri {

    fun parse(uri: String): Account {
        val parsed = Uri.parse(uri.trim())
        if (parsed.scheme != "otpauth") {
            throw IllegalArgumentException("Not an otpauth URI")
        }
        if (parsed.host != "totp") {
            throw IllegalArgumentException("Only otpauth://totp/ URIs are supported")
        }

        val secret = parsed.getQueryParameter("secret")
            ?: throw IllegalArgumentException("URI has no secret parameter")

        // Label is the path, optionally prefixed with "Issuer:".
        val rawLabel = parsed.path?.removePrefix("/") ?: ""
        val issuerParam = parsed.getQueryParameter("issuer")
        val labelPrefix = rawLabel.substringBefore(':', "").takeIf { rawLabel.contains(':') }
        val issuer = issuerParam ?: labelPrefix ?: Branding.ISSUER
        val label = rawLabel.substringAfter(':', rawLabel).ifBlank { "account" }

        return Account(
            label = label,
            issuer = issuer,
            secret = secret,
            algorithm = parsed.getQueryParameter("algorithm") ?: "SHA1",
            digits = parsed.getQueryParameter("digits")?.toIntOrNull() ?: 6,
            period = parsed.getQueryParameter("period")?.toIntOrNull() ?: 30,
        )
    }
}

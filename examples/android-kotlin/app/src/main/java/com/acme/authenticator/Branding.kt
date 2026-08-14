package com.acme.authenticator

/**
 * Whitelabel configuration.
 *
 * These constants mirror ../branding.json, which is the canonical reference.
 * To rebrand the app: edit the values below AND branding.json, update
 * res/values/colors.xml and res/values/strings.xml to match, replace
 * res/drawable/ic_launcher.xml, and change the namespace/applicationId in
 * app/build.gradle to com.<packageSuffix>.authenticator.
 */
object Branding {
    const val APP_NAME = "Acme Authenticator"
    const val ISSUER = "Acme"
    const val PACKAGE_SUFFIX = "acme"
    const val PRIMARY_COLOR = "#1B3A6B"
    const val ACCENT_COLOR = "#E8A020"
    const val LOGO_PATH = "app/src/main/res/drawable/ic_launcher.xml"
}

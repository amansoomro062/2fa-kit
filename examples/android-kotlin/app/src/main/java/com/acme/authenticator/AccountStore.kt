package com.acme.authenticator

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import org.json.JSONArray
import org.json.JSONObject

/**
 * Stores accounts in EncryptedSharedPreferences: keys and values are
 * encrypted with a master key kept in the Android Keystore, so secrets are
 * never written to disk in plaintext.
 */
class AccountStore(context: Context) {

    private val prefs = EncryptedSharedPreferences.create(
        context,
        "accounts",
        MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )

    fun list(): List<Account> {
        val json = prefs.getString(KEY_ACCOUNTS, "[]") ?: "[]"
        val array = JSONArray(json)
        return (0 until array.length()).map { i ->
            val o = array.getJSONObject(i)
            Account(
                label = o.getString("label"),
                issuer = o.getString("issuer"),
                secret = o.getString("secret"),
                algorithm = o.optString("algorithm", "SHA1"),
                digits = o.optInt("digits", 6),
                period = o.optInt("period", 30),
            )
        }
    }

    fun add(account: Account) {
        save(list() + account)
    }

    fun remove(account: Account) {
        save(list().filterNot { it == account })
    }

    private fun save(accounts: List<Account>) {
        val array = JSONArray()
        for (a in accounts) {
            array.put(
                JSONObject()
                    .put("label", a.label)
                    .put("issuer", a.issuer)
                    .put("secret", a.secret)
                    .put("algorithm", a.algorithm)
                    .put("digits", a.digits)
                    .put("period", a.period)
            )
        }
        prefs.edit().putString(KEY_ACCOUNTS, array.toString()).apply()
    }

    private companion object {
        const val KEY_ACCOUNTS = "accounts_json"
    }
}

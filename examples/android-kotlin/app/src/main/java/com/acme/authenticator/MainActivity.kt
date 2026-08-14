package com.acme.authenticator

import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView

/**
 * Single-activity app: a list of accounts with live 6-digit codes that
 * refresh every second, an add dialog accepting a pasted otpauth:// URI,
 * and delete via long-press with a confirm dialog.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var store: AccountStore
    private lateinit var adapter: AccountAdapter

    private val handler = Handler(Looper.getMainLooper())
    private val ticker = object : Runnable {
        override fun run() {
            adapter.refreshCodes()
            handler.postDelayed(this, 1000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        store = AccountStore(this)

        findViewById<TextView>(R.id.headerTitle).text = Branding.APP_NAME

        adapter = AccountAdapter(
            accounts = store.list().toMutableList(),
            onDeleteRequest = { account -> confirmDelete(account) },
        )
        findViewById<RecyclerView>(R.id.accountList).apply {
            layoutManager = LinearLayoutManager(this@MainActivity)
            adapter = this@MainActivity.adapter
        }

        findViewById<View>(R.id.addButton).setOnClickListener { showAddDialog() }
    }

    override fun onResume() {
        super.onResume()
        handler.post(ticker)
    }

    override fun onPause() {
        super.onPause()
        handler.removeCallbacks(ticker)
    }

    private fun showAddDialog() {
        val view = layoutInflater.inflate(R.layout.dialog_add_account, null)
        val uriInput = view.findViewById<EditText>(R.id.uriInput)
        AlertDialog.Builder(this)
            .setTitle(R.string.add_account)
            .setView(view)
            .setPositiveButton(android.R.string.ok) { _, _ ->
                try {
                    val account = OtpAuthUri.parse(uriInput.text.toString())
                    store.add(account)
                    adapter.addAccount(account)
                } catch (e: Exception) {
                    Toast.makeText(this, getString(R.string.invalid_uri, e.message), Toast.LENGTH_LONG).show()
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun confirmDelete(account: Account) {
        AlertDialog.Builder(this)
            .setTitle(R.string.delete_account_title)
            .setMessage(getString(R.string.delete_account_message, account.label))
            .setPositiveButton(R.string.delete) { _, _ ->
                store.remove(account)
                adapter.removeAccount(account)
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private class AccountAdapter(
        private val accounts: MutableList<Account>,
        private val onDeleteRequest: (Account) -> Unit,
    ) : RecyclerView.Adapter<AccountAdapter.VH>() {

        class VH(view: View) : RecyclerView.ViewHolder(view) {
            val issuer: TextView = view.findViewById(R.id.accountIssuer)
            val label: TextView = view.findViewById(R.id.accountLabel)
            val code: TextView = view.findViewById(R.id.accountCode)
            val progress: ProgressBar = view.findViewById(R.id.accountProgress)
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
            val view = LayoutInflater.from(parent.context)
                .inflate(R.layout.item_account, parent, false)
            return VH(view)
        }

        override fun getItemCount(): Int = accounts.size

        override fun onBindViewHolder(holder: VH, position: Int) {
            val account = accounts[position]
            holder.issuer.text = account.issuer
            holder.label.text = account.label
            try {
                holder.code.text = Totp.generate(account.secret, account.totpParams)
                val period = account.totpParams.period
                holder.progress.max = period
                holder.progress.progress = Totp.remaining(period)
            } catch (e: Exception) {
                holder.code.text = holder.itemView.context.getString(R.string.bad_secret)
            }
            holder.itemView.setOnLongClickListener {
                onDeleteRequest(account)
                true
            }
        }

        /** Called once per second to recompute every visible code. */
        fun refreshCodes() {
            notifyItemRangeChanged(0, accounts.size)
        }

        fun addAccount(account: Account) {
            accounts.add(account)
            notifyItemInserted(accounts.size - 1)
        }

        fun removeAccount(account: Account) {
            val index = accounts.indexOf(account)
            if (index >= 0) {
                accounts.removeAt(index)
                notifyItemRemoved(index)
            }
        }
    }
}

import SwiftUI

/// Main screen: one row per account, live 6-digit code, per-second refresh
/// with a remaining-time indicator. Swipe a row to delete (with confirmation).
struct AccountsListView: View {
    @EnvironmentObject private var store: AccountStore
    @State private var showingAdd = false
    @State private var pendingDelete: Account?
    @State private var now = Date()

    private let ticker = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    var body: some View {
        NavigationStack {
            List {
                ForEach(store.accounts) { account in
                    AccountRow(account: account, now: now)
                        .swipeActions {
                            Button(role: .destructive) {
                                pendingDelete = account
                            } label: {
                                Label("Delete", systemImage: "trash")
                            }
                        }
                }
            }
            .navigationTitle(Branding.appName)
            .toolbar {
                Button {
                    showingAdd = true
                } label: {
                    Image(systemName: "plus")
                }
            }
            .overlay {
                if store.accounts.isEmpty {
                    VStack(spacing: 8) {
                        Image(systemName: "key")
                            .font(.largeTitle)
                            .foregroundStyle(.secondary)
                        Text("No accounts")
                            .font(.headline)
                        Text("Tap + and paste an otpauth:// URI to add one.")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .sheet(isPresented: $showingAdd) {
                AddAccountView()
            }
            .alert("Delete account?", isPresented: Binding(
                get: { pendingDelete != nil },
                set: { if !$0 { pendingDelete = nil } }
            )) {
                Button("Delete", role: .destructive) {
                    if let account = pendingDelete {
                        store.delete(account)
                    }
                    pendingDelete = nil
                }
                Button("Cancel", role: .cancel) {
                    pendingDelete = nil
                }
            } message: {
                Text("This removes \(pendingDelete?.label ?? "this account") and its secret from the Keychain.")
            }
            .onReceive(ticker) { now = $0 }
        }
    }
}

/// One account row: issuer/label, current code, remaining-time bar.
struct AccountRow: View {
    let account: Account
    let now: Date

    var body: some View {
        let result = account.totpParameters.map { Totp.code(for: $0, at: now) }
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                if !account.issuer.isEmpty {
                    Text(account.issuer)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Text(account.label)
                    .font(.headline)
                if let result {
                    Text(grouped(result.code))
                        .font(.system(.title2, design: .monospaced).weight(.semibold))
                        .foregroundStyle(Branding.primaryColor)
                } else {
                    Text("Invalid secret")
                        .font(.callout)
                        .foregroundStyle(.red)
                }
            }
            Spacer()
            if let result {
                VStack(spacing: 4) {
                    Text("\(result.remaining)")
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.secondary)
                    ProgressView(
                        value: Double(result.remaining),
                        total: Double(max(account.period, 1))
                    )
                    .frame(width: 60)
                    .tint(result.remaining <= 5 ? .red : Branding.accentColor)
                }
            }
        }
        .padding(.vertical, 4)
    }

    /// "123456" -> "123 456" for readability.
    private func grouped(_ code: String) -> String {
        guard code.count > 3 else { return code }
        let split = code.index(code.startIndex, offsetBy: code.count / 2)
        return "\(code[..<split]) \(code[split...])"
    }
}

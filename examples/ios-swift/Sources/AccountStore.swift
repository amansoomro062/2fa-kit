import Foundation

/// Observable list of accounts. The whole list (including secrets) is stored
/// as one JSON blob in the Keychain, so secrets never touch UserDefaults or
/// plain files.
@MainActor
final class AccountStore: ObservableObject {
    @Published private(set) var accounts: [Account] = []

    private let keychainKey = "accounts"

    init() {
        load()
    }

    func add(_ account: Account) {
        accounts.append(account)
        persist()
    }

    func delete(_ account: Account) {
        accounts.removeAll { $0.id == account.id }
        persist()
    }

    private func persist() {
        guard let data = try? JSONEncoder().encode(accounts) else { return }
        KeychainHelper.save(data, account: keychainKey)
    }

    private func load() {
        guard let data = KeychainHelper.load(account: keychainKey),
              let decoded = try? JSONDecoder().decode([Account].self, from: data) else {
            return
        }
        accounts = decoded
    }
}

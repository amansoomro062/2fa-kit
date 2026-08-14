import SwiftUI

@main
struct AuthenticatorApp: App {
    @StateObject private var store = AccountStore()

    var body: some Scene {
        WindowGroup {
            AccountsListView()
                .environmentObject(store)
                .tint(Branding.primaryColor)
        }
    }
}

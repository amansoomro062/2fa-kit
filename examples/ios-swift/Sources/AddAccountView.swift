import SwiftUI
import UIKit

/// Add an account by pasting an otpauth:// URI, as produced by 2fa-kit's
/// buildUri() (usually displayed as a QR code on the server side).
struct AddAccountView: View {
    @EnvironmentObject private var store: AccountStore
    @Environment(\.dismiss) private var dismiss

    @State private var uri = ""
    @State private var errorMessage: String?

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextEditor(text: $uri)
                        .frame(minHeight: 80)
                        .font(.system(.body, design: .monospaced))
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                    Button {
                        if let pasted = UIPasteboard.general.string {
                            uri = pasted
                        }
                    } label: {
                        Label("Paste from clipboard", systemImage: "doc.on.clipboard")
                    }
                } header: {
                    Text("otpauth:// URI")
                } footer: {
                    Text("Get this from your \(Branding.issuer) account's 2FA setup page.")
                }

                if let errorMessage {
                    Section {
                        Text(errorMessage)
                            .foregroundStyle(.red)
                    }
                }
            }
            .navigationTitle("Add account")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Add") { add() }
                        .disabled(uri.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
            }
        }
    }

    private func add() {
        switch OtpauthParser.parse(uri) {
        case .success(let account):
            store.add(account)
            dismiss()
        case .failure(let error):
            errorMessage = error.errorDescription
        }
    }
}

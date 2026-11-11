import SwiftUI
import NexusCore

/// Services → One Time Passcode: the 4-digit code that unlocks Nexus Desktop on
/// Windows. Changes every 20 seconds. The pairing key comes from Nexus Desktop
/// (Settings → App lock → Set up with iPhone) and is kept in this device's Keychain.
struct OneTimePasscodeView: View {
    @Bindable var store: AppStore
    @State private var secret: Data?
    @State private var keyText = ""
    @State private var error: String?
    @State private var confirmRemove = false

    var body: some View {
        NexusList {
            if let secret {
                Section {
                    TimelineView(.periodic(from: .now, by: 1)) { context in
                        let remaining = OneTimePasscode.secondsRemaining(at: context.date)
                        VStack(spacing: 12) {
                            Text(OneTimePasscode.formatted(secret: secret, at: context.date))
                                .font(.system(size: 56, weight: .semibold, design: .monospaced))
                                .kerning(10)
                                .contentTransition(.numericText())
                                .accessibilityIdentifier("otp.code")
                            ProgressView(value: Double(remaining), total: OneTimePasscode.period)
                                .tint(remaining <= 5 ? .orange : .accentColor)
                            Text("New code in \(remaining) s")
                                .font(.caption.monospacedDigit())
                                .foregroundStyle(.secondary)
                        }
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 12)
                        .accessibilityElement(children: .combine)
                    }
                } footer: {
                    Text("Enter this code on the Nexus Desktop lock screen. Your iPhone and PC clocks must be within about 20 seconds of each other.")
                }
                Section {
                    Button("Remove pairing", systemImage: "trash", role: .destructive) { confirmRemove = true }
                } footer: {
                    Text("Removing it here does not turn off the lock on the PC. Pair again from Nexus Desktop if you replace this iPhone.")
                }
            } else {
                Section {
                    TextField("XXXX-XXXX-XXXX-XXXX", text: $keyText)
                        .font(.body.monospaced())
                        .textInputAutocapitalization(.characters)
                        .autocorrectionDisabled()
                        .accessibilityIdentifier("otp.pairing-key")
                    Button("Pair with Nexus Desktop", systemImage: "link") { pair() }
                        .disabled(OneTimePasscode.pairingSecret(keyText) == nil)
                } header: {
                    Text("Pair with Nexus Desktop")
                } footer: {
                    Text("On your PC, open Nexus Desktop → Settings → App lock → Set up with iPhone, then type the 16-character key shown there. Then enter the code this screen shows on the PC to finish.")
                }
            }
            if let error {
                Section { Text(error).foregroundStyle(.red) }
            }
        }
        .navigationTitle("One Time Passcode")
        .onAppear(perform: load)
        .confirmationDialog("Remove the Nexus Desktop pairing?", isPresented: $confirmRemove, titleVisibility: .visible) {
            Button("Remove", role: .destructive) { remove() }
        }
    }

    private func load() {
        do {
            secret = try store.secrets.read(OneTimePasscode.keychainAccount).flatMap { OneTimePasscode.pairingSecret(String(decoding: $0, as: UTF8.self)) }
        } catch {
            self.error = "Could not read the pairing key: \(error.localizedDescription)"
        }
    }

    private func pair() {
        guard let data = OneTimePasscode.pairingSecret(keyText) else { return }
        do {
            try store.secrets.write(Data(OneTimePasscode.encode(data).utf8), account: OneTimePasscode.keychainAccount)
            secret = data
            keyText = ""
            error = nil
        } catch {
            self.error = "Could not save the pairing key: \(error.localizedDescription)"
        }
    }

    private func remove() {
        do {
            try store.secrets.delete(OneTimePasscode.keychainAccount)
            secret = nil
        } catch {
            self.error = "Could not remove the pairing key: \(error.localizedDescription)"
        }
    }
}

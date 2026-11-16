import SwiftUI
import NexusCore
#if canImport(VisionKit) && os(iOS)
import VisionKit
#endif

/// Services → Nexus sign-in: the 6-digit code auth.liamjc.dev asks for after your password.
/// The key comes from Keycloak's "Set up your authenticator" page (QR code or "Unable to scan?" key)
/// and is kept in this device's Keychain only (never synced).
struct SignInPasscodeView: View {
    @Bindable var store: AppStore
    @State private var passcode: SignInPasscode?
    @State private var keyText = ""
    @State private var error: String?
    @State private var scanning = false
    @State private var confirmRemove = false

    var body: some View {
        NexusList {
            if let passcode {
                Section {
                    TimelineView(.periodic(from: .now, by: 1)) { context in
                        let remaining = passcode.secondsRemaining(at: context.date)
                        VStack(spacing: 12) {
                            Text(passcode.displayCode(at: context.date))
                                .font(.system(size: 52, weight: .semibold, design: .monospaced))
                                .contentTransition(.numericText())
                                .textSelection(.enabled)
                                .accessibilityIdentifier("signin.code")
                            ProgressView(value: Double(remaining), total: Double(passcode.period))
                                .tint(remaining <= 5 ? .orange : .accentColor)
                            Text("New code in \(remaining) s")
                                .font(.caption.monospacedDigit())
                                .foregroundStyle(.secondary)
                        }
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 12)
                        .accessibilityElement(children: .combine)
                    }
                } header: {
                    Text(passcode.account.isEmpty ? "Nexus sign-in" : passcode.account)
                } footer: {
                    Text("Enter this code at auth.liamjc.dev after your password. Never type it anywhere else: Nexus will never ask for it by message or email.")
                }
                Section {
                    Button("Remove sign-in code", systemImage: "trash", role: .destructive) { confirmRemove = true }
                } footer: {
                    Text("Only remove it after setting up a new phone, or you will need the admin console to sign in again.")
                }
            } else {
                Section {
                    if scannerAvailable {
                        Button("Scan QR code", systemImage: "qrcode.viewfinder") { scanning = true }
                    }
                    TextField("Paste the key or otpauth:// link", text: $keyText, axis: .vertical)
                        .font(.body.monospaced())
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .accessibilityIdentifier("signin.key")
                    Button("Add", systemImage: "plus") { add(keyText) }
                        .disabled(SignInPasscode.parse(keyText) == nil)
                } header: {
                    Text("Set up Nexus sign-in")
                } footer: {
                    Text("Sign in at auth.liamjc.dev. When it shows \"Set up your authenticator\", scan the QR code here, or tap \"Unable to scan?\" and paste the key. Then type the code this screen shows to finish.")
                }
            }
            if let error {
                Section { Text(error).foregroundStyle(.red) }
            }
        }
        .navigationTitle("Nexus sign-in")
        .onAppear(perform: load)
        .sheet(isPresented: $scanning) { scannerSheet }
        .confirmationDialog("Remove the Nexus sign-in code from this iPhone?", isPresented: $confirmRemove, titleVisibility: .visible) {
            Button("Remove", role: .destructive) { remove() }
        }
    }

    private var scannerAvailable: Bool {
        #if canImport(VisionKit) && os(iOS)
        return DataScannerViewController.isSupported
        #else
        return false
        #endif
    }

    @ViewBuilder private var scannerSheet: some View {
        #if canImport(VisionKit) && os(iOS)
        NavigationStack {
            QRCodeScanner { value in
                scanning = false
                add(value)
            }
            .ignoresSafeArea()
            .navigationTitle("Scan QR code")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { scanning = false } } }
        }
        #endif
    }

    private func load() {
        do {
            passcode = try store.secrets.read(SignInPasscode.keychainAccount).flatMap { try? JSONDecoder().decode(SignInPasscode.self, from: $0) }
        } catch {
            self.error = "Could not read the sign-in key: \(error.localizedDescription)"
        }
    }

    private func add(_ text: String) {
        guard let parsed = SignInPasscode.parse(text) else {
            error = "That isn't a valid sign-in key. Scan the QR code from auth.liamjc.dev, or paste the key it shows under \"Unable to scan?\"."
            return
        }
        do {
            try store.secrets.write(JSONEncoder().encode(parsed), account: SignInPasscode.keychainAccount)
            passcode = parsed
            keyText = ""
            error = nil
        } catch {
            self.error = "Could not save the sign-in key: \(error.localizedDescription)"
        }
    }

    private func remove() {
        do {
            try store.secrets.delete(SignInPasscode.keychainAccount)
            passcode = nil
        } catch {
            self.error = "Could not remove the sign-in key: \(error.localizedDescription)"
        }
    }
}

#if canImport(VisionKit) && os(iOS)
/// Camera QR reader (VisionKit). Reports the first QR payload, then stops.
private struct QRCodeScanner: UIViewControllerRepresentable {
    let onCode: (String) -> Void

    func makeUIViewController(context: Context) -> DataScannerViewController {
        let scanner = DataScannerViewController(recognizedDataTypes: [.barcode(symbologies: [.qr])],
                                                qualityLevel: .balanced, isHighlightingEnabled: true)
        scanner.delegate = context.coordinator
        return scanner
    }

    func updateUIViewController(_ scanner: DataScannerViewController, context: Context) {
        if DataScannerViewController.isAvailable, !scanner.isScanning { try? scanner.startScanning() }
    }

    func makeCoordinator() -> Coordinator { Coordinator(onCode: onCode) }

    final class Coordinator: NSObject, DataScannerViewControllerDelegate {
        private let onCode: (String) -> Void
        private var done = false
        init(onCode: @escaping (String) -> Void) { self.onCode = onCode }

        func dataScanner(_ scanner: DataScannerViewController, didAdd addedItems: [RecognizedItem], allItems: [RecognizedItem]) {
            guard !done else { return }
            for case let .barcode(code) in addedItems {
                guard let value = code.payloadStringValue else { continue }
                done = true
                scanner.stopScanning()
                onCode(value)
                return
            }
        }
    }
}
#endif

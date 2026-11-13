import SwiftUI
import UniformTypeIdentifiers
import Foundation
import UIKit
import NexusCore
import NexusSSH

enum ManagementRoute: Hashable { case devices }

struct RootView: View {
    @Bindable var store: AppStore
    @State private var aiConnections: AIConnectionsStore
    @State private var tab = 0
    @State private var terminalPath: [UUID] = []
    @State private var showSessions = false
    @State private var deviceEditor: Device?
    init(store: AppStore) {
        self.store = store
        let ai = AIConnectionsStore(secrets: store.secrets, isDemo: store.isDemoMode)
        _aiConnections = State(initialValue: ai)
        if !store.isDemoMode {
            Task {
                await SSHConnectionPipeline.shared.installCloudflareAccessTokenProvider {
                    try await ai.cloudflareSSHAccessToken()
                }
            }
        }
    }
    private func openTerminal(_ device: Device) {
        let session = store.open(device)
        tab = 1
        terminalPath.append(session.id)
    }

    var body: some View {
        TabView(selection: $tab) {
            NavigationStack {
                DashboardView(store: store, onOpen: openTerminal,
                    onOpenDevices: { tab = 1 }, onOpenSessions: { tab = 1; showSessions = true }, onOpenAI: { tab = 2 },
                    onOpenServices: { tab = 3 }, onOpenSettings: { tab = 4 },
                    aiConnectionCount: aiConnections.connections.filter(\.enabled).count,
                    aiSummary: aiConnections.overviewSummary,
                    isActive: tab == 0)
            }
                .tabItem { Label("Overview", systemImage: "square.grid.2x2") }.tag(0)
            NavigationStack(path: $terminalPath) {
                DevicesView(store: store, onOpen: openTerminal)
                    .navigationDestination(isPresented: $showSessions) {
                        SessionsView(store: store, onOpen: openTerminal)
                            .toolbar(.hidden, for: .tabBar)
                    }
                    .navigationDestination(for: UUID.self) { id in
                        if let session = store.sessions.first(where: { $0.id == id }) {
                            TerminalScreen(session: session, fontSize: store.fontSize, onEditExampleDevice: {
                                store.close(session)
                                terminalPath.removeAll { $0 == session.id }
                                deviceEditor = session.device
                                tab = 1
                            })
                            .toolbar(.hidden, for: .tabBar)
                        } else {
                            ContentUnavailableView("Session closed", systemImage: "terminal",
                                description: Text("Return to Devices and open another session."))
                        }
                    }
            }
                .tabItem { Label("Devices", systemImage: "server.rack") }.tag(1)
            NavigationStack { NativeAIChatView(ai: aiConnections, store: store) }
                .tabItem { Label("AI", systemImage: "sparkles") }.tag(2)
            NavigationStack {
                ServicesHomeView(store: store)
                    .navigationDestination(for: ManagementRoute.self) { route in
                        switch route {
                        case .devices: DevicesView(store: store, onOpen: openTerminal)
                        }
                    }
            }
                .tabItem { Label("Services", systemImage: "gearshape.2") }.tag(3)
            NavigationStack { SettingsView(store: store, aiConnections: aiConnections) }
                .tabItem { Label("Settings", systemImage: "gearshape") }.tag(4)
        }
        .tint(NexusPalette.blue)
        // The system tab bar owns its safe area and keyboard transitions. The
        // previous floating overlay could cover the AI composer on iPhone.
        .modifier(NexusTabBarBackground())
        .alert("Nexus", isPresented: Binding(get: { store.error != nil }, set: { if !$0 { store.error = nil } })) {
            Button("OK") { store.error = nil }
        } message: { Text(store.error ?? "") }
        .safeAreaInset(edge: .top, spacing: 0) {
            if store.isDemoMode {
                Label("DEMO · simulated data only", systemImage: "sparkles")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.cyan)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 7)
                    .background(.bar)
            }
        }
        .sheet(item: $deviceEditor) { device in
            NavigationStack { DeviceEditor(store: store, device: device) }
                .presentationDetents([.large])
                .presentationDragIndicator(.visible)
        }
    }
}

/// iOS 26 draws its own floating Liquid Glass bar; overriding it dulls the glass.
private struct NexusTabBarBackground: ViewModifier {
    func body(content: Content) -> some View {
        if #available(iOS 26, *) {
            content
        } else {
            content
                .toolbarBackground(.ultraThinMaterial, for: .tabBar)
                .toolbarBackground(.visible, for: .tabBar)
        }
    }
}

struct DevicesView: View {
    @Bindable var store: AppStore
    let onOpen: (Device) -> Void
    @State private var editing: Device?
    @State private var deleting: Device?
    @State private var showingDetails: Device?
    @State private var pendingTerminalFromDetails: Device?
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    private func presentNewDevice() {
        editing = Device(name: "", username: "", endpoints: [.init(host: "")])
    }
    var body: some View {
        Group {
            if store.devices.isEmpty {
                VStack(spacing: 0) {
                    header.padding(.horizontal, NexusLayout.screenInset)
                    ContentUnavailableView {
                        Label("Add a device", systemImage: "server.rack")
                    } description: {
                        Text("Save an SSH connection to open terminals, browse files, and manage services.")
                    } actions: {
                        Button("Add device") { presentNewDevice() }
                            .buttonStyle(.borderedProminent)
                            .accessibilityIdentifier("devices.empty.add")
                    }
                }
            } else {
                ScrollView {
                    LazyVStack(spacing: NexusLayout.standardSpacing) {
                        header
                        ForEach(store.devices) { device in
                            deviceCard(device)
                        }
                        sessionsCard
                    }
                    .padding(.horizontal, NexusLayout.screenInset)
                    .padding(.bottom, NexusLayout.standardSpacing)
                    .frame(maxWidth: 760, alignment: .leading)
                    .frame(maxWidth: .infinity)
                }
                .scrollIndicators(.hidden)
            }
        }
        .navigationTitle("Devices")
        .toolbar(.hidden, for: .navigationBar)
        .nexusScreenBackground()
        .scrollContentBackground(.hidden)
        .sheet(item: $editing) { device in
            NavigationStack { DeviceEditor(store: store, device: device) }
                .presentationDetents([.large])
                .presentationDragIndicator(.visible)
        }
        .sheet(item: $showingDetails, onDismiss: {
            guard let device = pendingTerminalFromDetails else { return }
            pendingTerminalFromDetails = nil
            guard store.devices.contains(where: { $0.id == device.id }) else { return }
            onOpen(device)
        }) { device in
            DeviceDetailSheet(store: store, deviceID: device.id) { selected in
                pendingTerminalFromDetails = selected
                showingDetails = nil
            }
        }
        .confirmationDialog(
            deleting.map { "Delete “\($0.name)”?" } ?? "Delete device?",
            isPresented: Binding(get: { deleting != nil }, set: { if !$0 { deleting = nil } })
        ) {
            Button("Delete", role: .destructive) {
                if let deleting { do { try store.remove(deleting) } catch { store.error = error.localizedDescription } }
                deleting = nil
            }
            Button("Cancel", role: .cancel) { deleting = nil }
        } message: {
            Text(store.isDemoMode
                ? "Removes this sample profile from the current preview only. No saved device, credential, or host key is changed."
                : "Removes this device from Nexus, its Keychain credential, host-key pins used only by this device, retained metrics history, Dashboard favorite, and related low-resource alerts. Shared pins used by other devices stay.")
        }
    }

    private var header: some View {
        NexusScreenHeader(title: "Devices", subtitle: "Tap to open a session") {
            Button { presentNewDevice() } label: {
                NexusRoundGlassLabel(systemImage: "plus")
            }
            .buttonStyle(.plain)
            .accessibilityLabel("Add device")
        }
    }

    private func deviceCard(_ device: Device) -> some View {
        let isConnected = store.sessions.contains { $0.device.id == device.id && $0.state == .connected }
        let isFavorite = store.favoriteDeviceIDs.contains(device.id)
        let endpoints = "\(device.endpoints.count) endpoint\(device.endpoints.count == 1 ? "" : "s")"

        return HStack(spacing: NexusLayout.microSpacing) {
            Button { onOpen(device) } label: {
                HStack(spacing: NexusLayout.standardSpacing) {
                    NexusIconTile(systemImage: "server.rack")
                    VStack(alignment: .leading, spacing: 2) {
                        HStack(spacing: 5) {
                            Text(device.name)
                                .font(.callout.weight(.semibold))
                                .foregroundStyle(NexusPalette.primaryText)
                                .multilineTextAlignment(.leading)
                            if isFavorite {
                                Image(systemName: "star.fill")
                                    .font(.caption2)
                                    .foregroundStyle(NexusPalette.amber)
                            }
                        }
                        Text("\(isConnected ? "Connected" : "Saved") · \(device.username) · \(endpoints)")
                            .font(NexusTypography.supporting)
                            .foregroundStyle(NexusPalette.secondaryText)
                            .multilineTextAlignment(.leading)
                    }
                    Spacer(minLength: 0)
                    NexusStatusDot(color: isConnected ? NexusPalette.green : NexusPalette.secondaryText.opacity(0.5),
                                   glows: isConnected)
                }
                .frame(minHeight: 44)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityElement(children: .ignore)
            .accessibilityLabel("Open terminal on \(device.name)")
            .accessibilityValue(isConnected ? "Connected" : "Saved")
            .accessibilityIdentifier("device.open-terminal")

            Menu {
                Button("Device details", systemImage: "info.circle") { showingDetails = device }
                    .accessibilityIdentifier("device.details")
                Button("Edit", systemImage: "pencil") { editing = device }
                Button(isFavorite ? "Remove from favorites" : "Add to favorites",
                       systemImage: isFavorite ? "star.slash" : "star") {
                    if reduceMotion { store.toggleFavorite(device) }
                    else { withAnimation(.easeInOut(duration: 0.2)) { store.toggleFavorite(device) } }
                }
                Button("Delete device", systemImage: "trash", role: .destructive) { deleting = device }
            } label: {
                Image(systemName: "ellipsis")
                    .font(.body.weight(.semibold))
                    .foregroundStyle(NexusPalette.secondaryText)
                    .frame(width: 44, height: 44)
                    .contentShape(Circle())
            }
            .accessibilityLabel("More actions for \(device.name)")
        }
        .padding(.leading, NexusLayout.cardPadding)
        .padding(.trailing, 5)
        .padding(.vertical, 11)
        .background(NexusGlassSurface())
    }

    private var sessionsCard: some View {
        let connected = store.sessions.filter { $0.state == .connected }.count
        return NavigationLink {
            SessionsView(store: store, onOpen: onOpen)
        } label: {
            NexusCard {
                VStack(alignment: .leading, spacing: NexusLayout.compactSpacing) {
                    HStack(spacing: NexusLayout.compactSpacing + 2) {
                        Image(systemName: "terminal")
                            .font(.system(size: 18, weight: .semibold))
                            .foregroundStyle(NexusPalette.green)
                        Text("SSH sessions")
                            .font(NexusTypography.cardTitle)
                            .foregroundStyle(NexusPalette.primaryText)
                        Spacer(minLength: 0)
                        Image(systemName: "chevron.right")
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(NexusPalette.secondaryText)
                    }
                    Text("\(connected) connected · \(store.sessions.count) open")
                        .font(NexusTypography.monospaced)
                        .foregroundStyle(connected > 0 ? NexusPalette.green : NexusPalette.secondaryText)
                }
            }
        }
        .buttonStyle(.plain)
        .accessibilityElement(children: .combine)
    }
}

struct DeviceEditor: View {
    let store: AppStore
    @State var device: Device
    @State private var secret = ""
    @State private var passphrase = ""
    @State private var importingKey = false
    @State private var importingKeyFolder = false
    @State private var importedKeyName: String?
    @State private var generatedPublicKey: String?
    @State private var copiedGeneratedPublicKey = false
    @State private var confirmingKeyGeneration = false
    @State private var keyFolderAccess: SSHKeyFolderAccess?
    @State private var error: String?
    @State private var isSaving = false
    @State private var keyImportGeneration = UUID()
    @Environment(\.dismiss) private var dismiss

    init(store: AppStore, device: Device) {
        self.store = store
        var keyOnlyDevice = device
        keyOnlyDevice.authentication = .ed25519
        if let target = Self.cloudflareTarget(for: keyOnlyDevice),
           let gatewayHost = DeploymentConfiguration.current.gatewayHost {
            keyOnlyDevice.endpoints = [.init(host: gatewayHost, port: 443,
                kind: .cloudflare, relayTarget: target)]
        }
        _device = State(initialValue: keyOnlyDevice)
    }

    private static func cloudflareTarget(for device: Device) -> String? {
        DeploymentConfiguration.current.relayTarget(forUsername: device.username)
    }

    private var cloudflareTarget: String? { Self.cloudflareTarget(for: device) }

    var body: some View {
        NexusForm {
            Section("Device") {
                TextField("Name", text: $device.name)
                    .accessibilityLabel("Device name")
                    .accessibilityIdentifier("device.name")
                TextField("SSH username", text: $device.username)
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                    .accessibilityLabel("SSH username")
                Toggle("Preserve remote shell with tmux", isOn: $device.useTmux)
                Text("Requires tmux on the server. A tab reattaches to its own remote session after reconnecting.").font(.caption)
            }
            if let cloudflareTarget {
                Section("Cloudflare SSH") {
                    Label("Connected through Cloudflare Access", systemImage: "lock.shield")
                    Text("Target: \(cloudflareTarget.capitalized) · \(device.username)")
                    Text("Nexus uses your signed-in Cloudflare API connection. SSH credentials stay on the Debian relay; this profile does not need an SSH key.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            } else {
            Section("Connection endpoints · lower priority first") {
                ForEach($device.endpoints) { $endpoint in
                    VStack(alignment: .leading) {
                        TextField("IP address or MagicDNS hostname", text: $endpoint.host)
                            .textInputAutocapitalization(.never).autocorrectionDisabled()
                            .accessibilityLabel("Endpoint hostname or IP address")
                        HStack {
                            Text("Port").frame(width: 38, alignment: .leading)
                            TextField("22", value: $endpoint.port, format: .number)
                                .keyboardType(.numberPad)
                                .frame(width: 68)
                                .accessibilityLabel("SSH port")
                            Spacer(minLength: 10)
                            Text("Priority")
                                .lineLimit(1)
                                .fixedSize(horizontal: true, vertical: false)
                            Stepper(value: $endpoint.priority, in: 0...99) {
                                Text("\(endpoint.priority)")
                                    .monospacedDigit()
                                    .frame(minWidth: 22)
                            }
                            .fixedSize(horizontal: true, vertical: false)
                            .accessibilityLabel("Priority")
                            .accessibilityValue("\(endpoint.priority)")
                            .accessibilityHint("Lower numbers are tried first.")
                            .accessibilityIdentifier("device.endpoint.priority")
                        }
                        Picker("Network", selection: $endpoint.kind) {
                            ForEach(EndpointKind.allCases, id: \.self) { Text($0.rawValue.capitalized).tag($0) }
                        }
                        if device.endpoints.count > 1 {
                            Button("Remove endpoint", role: .destructive) { device.endpoints.removeAll { $0.id == endpoint.id } }
                                .accessibilityLabel("Remove endpoint \(endpoint.host.isEmpty ? "with blank address" : endpoint.host)")
                        }
                    }
                }
                Button("Add endpoint") { device.endpoints.append(.init(host: "", kind: .tailscale, priority: device.endpoints.count)) }
            }
            }
            if store.isDemoMode {
                Section("Preview profile") {
                    Label("No credential or host key is loaded", systemImage: "lock.shield")
                    Text("Profile edits stay in temporary preview memory and never touch saved Nexus profiles or Keychain items.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            } else {
            if cloudflareTarget == nil && !device.endpoints.allSatisfy({ $0.kind == .cloudflare }) {
            Section("Authentication · stored in Keychain") {
                Text("Ed25519 OpenSSH private key")
                    .font(.headline)
                Text("Choose a private key file. Nexus stores the key and its passphrase only in this device’s Keychain.")
                    .font(.caption)
                    .fixedSize(horizontal: false, vertical: true)
                Button("Choose private key file", systemImage: "key.horizontal") { importingKey = true }
                    .accessibilityIdentifier("device.key-file.choose")
                Button("Browse key folder", systemImage: "folder") { importingKeyFolder = true }
                    .accessibilityIdentifier("device.key-folder.choose")
                Button("Generate new Ed25519 key", systemImage: "key.horizontal.fill") {
                    confirmingKeyGeneration = true
                }
                .accessibilityIdentifier("device.key.generate")
                if let generatedPublicKey {
                    Text("Public key · copy this line and add it to the remote account's authorized_keys. Nexus does not install keys on servers.")
                        .font(.caption)
                        .fixedSize(horizontal: false, vertical: true)
                    Text(generatedPublicKey)
                        .font(.caption2.monospaced())
                        .textSelection(.enabled)
                        .privacySensitive(false)
                        .accessibilityLabel("Generated public SSH key")
                    Button(copiedGeneratedPublicKey ? "Public key copied" : "Copy public key", systemImage: copiedGeneratedPublicKey ? "checkmark" : "doc.on.doc") {
                        UIPasteboard.general.string = generatedPublicKey
                        copiedGeneratedPublicKey = true
                    }
                    .accessibilityIdentifier("device.key.copy-public")
                }
                if let keyFolderAccess {
                    Text("Choose the private key from \(keyFolderAccess.directory.lastPathComponent)")
                        .font(.caption.weight(.medium))
                    ForEach(keyFolderAccess.files, id: \.path) { file in
                        Button(file.lastPathComponent, systemImage: "key") {
                            importPrivateKey(from: file, removePickerCopy: false)
                        }
                        .lineLimit(1)
                        .accessibilityIdentifier("device.key-folder.file.\(file.lastPathComponent)")
                        .accessibilityLabel("Import private key file \(file.lastPathComponent)")
                    }
                }
                if let importedKeyName {
                    Label(importedKeyName, systemImage: "checkmark.circle.fill")
                        .font(.caption).foregroundStyle(.secondary)
                } else {
                    Text("Select a private key file to connect. Paste-based key entry is unavailable.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                if generatedPublicKey != nil {
                    Label("This generated key has no separate passphrase. Nexus stores its private half in this device’s Keychain when you save.", systemImage: "lock.shield")
                        .font(.caption)
                        .fixedSize(horizontal: false, vertical: true)
                } else {
                    SecureField("Key passphrase (if encrypted)", text: $passphrase)
                        .textContentType(.password)
                        .privacySensitive()
                        .accessibilityLabel("Private key passphrase")
                }
                Text("Existing password-based profiles must be updated with an Ed25519 key before connecting. Credentials are excluded from configuration exports.")
                    .font(.caption)
            }
            }
            }
        }
        .navigationTitle("Connection settings")
        .scrollContentBackground(.hidden)
        .nexusScreenBackground()
        .tint(NexusPalette.blue)
        .confirmationDialog("Generate an Ed25519 key for this device?", isPresented: $confirmingKeyGeneration, titleVisibility: .visible) {
            Button("Generate key") { generateKeyPair() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(secret.isEmpty
                ? "Nexus will save the private key in this device’s Keychain when you tap Save. Copy the public key and add it to the remote account before connecting."
                : "This replaces the key draft in this editor. The saved Keychain credential changes only when you tap Save.")
        }
        .onDisappear {
            keyImportGeneration = UUID()
            secret = ""
            passphrase = ""
            importedKeyName = nil
            generatedPublicKey = nil
        }
        .toolbar {
            ToolbarItem(placement: .cancellationAction) { Button("Cancel") { keyFolderAccess = nil; dismiss() }.disabled(isSaving) }
            ToolbarItem(placement: .confirmationAction) {
                Button {
                    guard !isSaving else { return }
                    isSaving = true
                    let snapshot = device
                    let candidateCredential = secret.isEmpty ? nil : Credential(secret: secret, passphrase: passphrase)
                    Task {
                    defer { isSaving = false }
                    do {
                        if secret.isEmpty && !store.isDemoMode {
                            let existing = store.devices.first(where: { $0.id == snapshot.id })
                            let savedKey = try store.secrets.read(SSHTransport.credentialAccount(snapshot))
                            guard snapshot.endpoints.allSatisfy({ $0.kind == .cloudflare }) ||
                                    (existing?.authentication == .ed25519 && savedKey != nil) else {
                                error = "Choose an Ed25519 private key file before saving this device."; return
                            }
                        }
                        if secret.isEmpty, !store.isDemoMode,
                           let old = store.devices.first(where: { $0.id == snapshot.id }), old.authentication != snapshot.authentication {
                            error = "Enter a credential for the new authentication method."; return
                        }
                        try await store.save(snapshot, credential: candidateCredential)
                        secret = ""; passphrase = ""; keyFolderAccess = nil; dismiss()
                    } catch { self.error = error.localizedDescription }
                    }
                } label: {
                    if isSaving { ProgressView() } else { Text("Save") }
                }
                .disabled(isSaving)
                .accessibilityIdentifier("device.save")
            }
        }
        .disabled(isSaving)
        .alert("Unable to save device", isPresented: Binding(
            get: { error != nil },
            set: { if !$0 { error = nil } }
        )) {
            Button("OK", role: .cancel) { error = nil }
        } message: {
            Text(error ?? "")
        }
        .fullScreenCover(isPresented: $importingKey) {
            SSHKeyDocumentPicker { url in
                importPrivateKey(from: url, removePickerCopy: true)
                importingKey = false
            } onCancel: {
                importingKey = false
            }
        }
        .fileImporter(isPresented: $importingKeyFolder, allowedContentTypes: [.folder], allowsMultipleSelection: false) { result in
            do {
                guard let url = try result.get().first else { return }
                loadKeyFolder(url)
            } catch {
                self.error = "Could not open the selected key folder: \(error.localizedDescription)"
            }
        }
    }

    private func loadKeyFolder(_ url: URL) {
        do {
            keyFolderAccess = try SSHKeyFolderAccess(directory: url)
        } catch {
            self.error = "Could not list files in the selected folder: \(error.localizedDescription)"
        }
    }

    private func importPrivateKey(from url: URL, removePickerCopy: Bool) {
        let token = UUID()
        keyImportGeneration = token
        let hasAccess = url.startAccessingSecurityScopedResource()
        let source = url
        let displayName = url.lastPathComponent
        Task {
            let result: Result<String, Error> = await Task.detached(priority: .userInitiated) {
                Result(catching: { try SSHPrivateKeyFile.read(source) })
            }.value
            if hasAccess { source.stopAccessingSecurityScopedResource() }
            if removePickerCopy {
                let temporary = FileManager.default.temporaryDirectory.standardizedFileURL.path
                let copied = source.standardizedFileURL.path
                if copied.hasPrefix(temporary.hasSuffix("/") ? temporary : temporary + "/") {
                    try? FileManager.default.removeItem(at: source)
                }
            }
            guard keyImportGeneration == token else { return }
            switch result {
            case .success(let contents):
                secret = contents
                importedKeyName = displayName
                generatedPublicKey = nil
                copiedGeneratedPublicKey = false
                keyFolderAccess = nil
            case .failure:
                error = "Could not import this file. Choose an OpenSSH private key no larger than 64 KiB. The key contents are never shown in an error."
            }
        }
    }

    private func generateKeyPair() {
        do {
            let pair = try SSHKeyGenerator.generate(comment: "nexus")
            try SSHTransport.validateCredential(for: device, credential: Credential(secret: pair.privateKey))
            secret = pair.privateKey
            passphrase = ""
            importedKeyName = "Generated on this device"
            generatedPublicKey = pair.publicKey
            copiedGeneratedPublicKey = false
            keyFolderAccess = nil
        } catch {
            self.error = "Nexus could not generate and validate an Ed25519 key. No device credentials were changed."
        }
    }
}

private final class SSHKeyFolderAccess {
    let directory: URL
    let files: [URL]
    private let holdsSecurityScope: Bool

    init(directory: URL) throws {
        let holdsScope = directory.startAccessingSecurityScopedResource()
        do {
            let candidates = try FileManager.default.contentsOfDirectory(at: directory,
                includingPropertiesForKeys: [.isRegularFileKey], options: [.skipsHiddenFiles])
                .filter { (try? $0.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true }
                .sorted { $0.lastPathComponent.localizedStandardCompare($1.lastPathComponent) == .orderedAscending }
            guard !candidates.isEmpty else {
                throw NSError(domain: "NexusKeyImport", code: 1,
                    userInfo: [NSLocalizedDescriptionKey: "The selected folder has no files. Choose the folder containing your SSH key."])
            }
            self.directory = directory
            self.files = candidates
            self.holdsSecurityScope = holdsScope
        } catch {
            if holdsScope { directory.stopAccessingSecurityScopedResource() }
            throw error
        }
    }

    deinit {
        if holdsSecurityScope { directory.stopAccessingSecurityScopedResource() }
    }
}

struct SettingsView: View {
    @Bindable var store: AppStore
    @Bindable var aiConnections: AIConnectionsStore
    @State private var importingConfiguration = false
    @State private var exportingConfiguration = false
    @State private var exportDocument = DeviceConfigurationDocument()
    @State private var pendingConfigurationData: Data?
    @State private var importSummary = ""
    @State private var confirmingConfigurationImport = false
    @State private var cloudflareSignInInProgress = false
    @State private var cloudflareSignInStatus: String?
    private var appVersionBuild: String {
        let info = Bundle.main.infoDictionary ?? [:]
        let version = info["CFBundleShortVersionString"] as? String ?? "Unknown"
        let build = info["CFBundleVersion"] as? String ?? "Unknown"
        return "\(version) (\(build))"
    }
    var body: some View {
        NexusForm {
            NexusScreenHeader(title: "Settings", subtitle: "Nexus \(appVersionBuild)")
                .listRowBackground(Color.clear)
                .listRowInsets(EdgeInsets())
                .listRowSeparator(.hidden)
            Section {
                NavigationLink {
                    AIConnectionsView(ai: aiConnections, devices: store.devices, store: store)
                } label: {
                    Label("API Connections", systemImage: "server.rack")
                }.accessibilityIdentifier("settings.ai.connections")
            } header: {
                settingsHeader("AI")
            } footer: {
                Text("Connect to NexusAI, Ollama, Open WebUI's API, or another compatible model service. The chat is native SwiftUI and sends directly to your configured service.")
            }
            if !store.isDemoMode, let cloudflareConnection = aiConnections.configuredCloudflareGatewayConnection {
                Section {
                    Button {
                        signInToCloudflare(cloudflareConnection)
                    } label: {
                        Label(cloudflareSignInInProgress ? "Opening Cloudflare sign-in…" :
                            (aiConnections.hasGatewaySession(for: cloudflareConnection)
                                ? "Sign in to Cloudflare again" : "Sign in to Cloudflare"),
                            systemImage: "person.crop.circle.badge.checkmark")
                    }
                    .disabled(cloudflareSignInInProgress)
                    .accessibilityIdentifier("settings.cloudflare.sign-in")
                    if aiConnections.hasGatewaySession(for: cloudflareConnection) {
                        Label("Connected · credentials are stored in Keychain", systemImage: "checkmark.shield.fill")
                            .font(.footnote).foregroundStyle(.secondary)
                    } else {
                        Text("Opens Cloudflare Access in the system sign-in sheet. Approve the request there to connect Nexus.")
                            .font(.footnote).foregroundStyle(.secondary)
                    }
                    if let cloudflareSignInStatus {
                        Text(cloudflareSignInStatus).font(.footnote).foregroundStyle(.secondary)
                    }
                    NavigationLink {
                        AIConnectionsView(ai: aiConnections, devices: store.devices, store: store)
                    } label: {
                        Label("Cloudflare connection settings", systemImage: "slider.horizontal.3")
                    }
                } header: {
                    settingsHeader("Cloudflare Access")
                }
            }
            Section {
                Picker("Theme", selection: $store.theme) {
                    Text("System").tag("system"); Text("Dark").tag("dark"); Text("Light").tag("light")
                }
                Slider(value: $store.fontSize, in: 10...26, step: 1) { Text("Terminal font size") }
                LabeledContent("Terminal font", value: "\(Int(store.fontSize)) pt · monospace")
            } header: {
                settingsHeader("Appearance")
            }
            Section {
                if store.isDemoMode {
                    Text("App lock, notification permissions, and real connection settings are disabled in this preview.")
                        .font(.footnote).foregroundStyle(.secondary)
                } else {
                Toggle("Require device authentication", isOn: Binding(get: { store.appLock }, set: { enabled in
                    Task { await store.setAppLock(enabled) }
                }))
                Toggle("Show favorite shortcuts on Dashboard", isOn: $store.showFavoriteShortcuts)
                Toggle("Low-resource notifications", isOn: Binding(get: { store.lowResourceAlerts }, set: { enabled in
                    Task { await store.setLowResourceAlerts(enabled) }
                }))
                Stepper("SSH/status timeout: \(store.timeout) seconds", value: $store.timeout, in: 3...120)
                }
            } header: {
                settingsHeader("Security and connection")
            } footer: {
                if !store.isDemoMode {
                    Text("Low-resource notifications follow a manual host refresh, when measured root disk space or available memory falls below 10%. No background polling is used.\n\nBackgrounding closes SSH connections, including recipe command sessions. If a recipe loses its connection, its outcome may be unknown; check the selected host before retrying. Reconnect terminal sessions manually; use tmux to preserve remote work. Nexus uses the existing Tailscale VPN and never publishes SSH ports.")
                }
            }
            if !store.isDemoMode {
            Section {
                Button("Export device profiles", systemImage: "square.and.arrow.up") {
                    do {
                        exportDocument = DeviceConfigurationDocument(data: try store.exportDeviceConfiguration())
                        exportingConfiguration = true
                    } catch {
                        store.error = "Could not export device profiles: \(error.localizedDescription)"
                    }
                }
                Button("Import device profiles", systemImage: "square.and.arrow.down") {
                    importingConfiguration = true
                }
            } header: {
                settingsHeader("Device configuration")
            } footer: {
                Text("This JSON contains device names, usernames, endpoints, and connection preferences only. Credentials and trusted host keys stay in Keychain. Import previews and asks before adding profiles or updating matching IDs. Profiles without credentials already saved on this device need credentials entered in Devices; authentication-method changes require editing the credential there.")
            }
            }
            Section {
                LabeledContent("Nexus version / build", value: appVersionBuild)
                    .accessibilityIdentifier("settings.app-version-build")
            } header: {
                settingsHeader("Build")
            } footer: {
                Text("Dashboard status and local history are collected only when you refresh over SSH. Files, services, network checks, and command recipes are manual. Confirmed service and recipe actions use only the server's existing permissions; Nexus does not change server policy. NixOS dry-build and switch controls require separate confirmations and remain unvalidated. Low-resource alerts are opt-in and based only on manual snapshots. Network-range scanning, configuration editing, and background scheduling remain future work. Minecraft opens the existing private panel; no server agent or background polling is installed.")
            }
        }
        .navigationTitle("Settings")
        .toolbar(.hidden, for: .navigationBar)
        .tint(NexusPalette.blue)
        .fileExporter(isPresented: $exportingConfiguration, document: exportDocument,
            contentType: .json, defaultFilename: "Nexus-device-profiles") { result in
                if case .failure(let error) = result {
                    if (error as? CocoaError)?.code != .userCancelled {
                        store.error = "Could not export device profiles: \(error.localizedDescription)"
                    }
                }
            }
        .fileImporter(isPresented: $importingConfiguration, allowedContentTypes: [.json],
            allowsMultipleSelection: false) { result in
                do {
                    guard let url = try result.get().first else { return }
                    let hasAccess = url.startAccessingSecurityScopedResource()
                    defer { if hasAccess { url.stopAccessingSecurityScopedResource() } }
                    let data = try store.readDeviceConfiguration(from: url)
                    let preview = try store.previewDeviceConfigurationImport(data)
                    pendingConfigurationData = data
                    importSummary = "Add \(preview.added) device profile(s) and update \(preview.updated) matching profile(s)? Credentials and host-key pins are never imported. Any profile without matching credentials already in this app needs credentials entered in Devices before connecting."
                    confirmingConfigurationImport = true
                } catch let error as CocoaError where error.code == .userCancelled {
                    return
                } catch {
                    store.error = "Could not import device profiles: \(error.localizedDescription)"
                }
            }
        .confirmationDialog("Review device profile import", isPresented: $confirmingConfigurationImport,
            titleVisibility: .visible) {
                Button("Import profiles") {
                    guard let pendingConfigurationData else { return }
                    do { try store.importDeviceConfiguration(pendingConfigurationData) }
                    catch { store.error = "Could not import device profiles: \(error.localizedDescription)" }
                    self.pendingConfigurationData = nil
                }
                Button("Cancel", role: .cancel) { pendingConfigurationData = nil }
            } message: {
                Text(importSummary)
            }
    }

    private func settingsHeader(_ title: String) -> some View {
        Text(title)
            .font(.footnote.weight(.semibold))
            .textCase(nil)
            .foregroundStyle(NexusPalette.secondaryText)
    }

    private func signInToCloudflare(_ connection: AIConnection) {
        cloudflareSignInInProgress = true
        cloudflareSignInStatus = nil
        Task {
            defer { cloudflareSignInInProgress = false }
            do {
                try await aiConnections.signInToGateway(connection)
                cloudflareSignInStatus = "Cloudflare sign-in completed. Nexus saved the session in Keychain."
            } catch {
                cloudflareSignInStatus = error.localizedDescription
            }
        }
    }
}

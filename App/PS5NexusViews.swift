import SwiftUI
import NexusCore

/// Non-secret PS5 management preferences only. Inference and management tokens
/// remain in their separate Keychain accounts.
struct PS5NexusSavedConfiguration: Codable {
    var enabled: Bool
    var managementURL: String
    var reuseConnectionCredential: Bool
}

/// Progress of a PS5 model load, shown wherever a load can be started or a
/// message sent. The store owns the load, so this survives its screen closing.
struct PS5ModelLoadStatusView: View {
    @Bindable var ai: AIConnectionsStore
    let connection: AIConnection

    private var load: PS5NexusModelLoadTracker.Entry? { ai.ps5ModelLoads.entry(for: connection.id) }

    var body: some View {
        if let load {
            HStack(spacing: 8) {
                if load.phase != .unconfirmed { ProgressView() }
                Text("Loading \(load.model.label)… Sending resumes when ready.")
                    .font(.footnote).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .accessibilityElement(children: .combine)
        }
        if let issue = ai.ps5ModelLoads.issue(for: connection.id) {
            Text(issue).font(.footnote).foregroundStyle(NexusPalette.red)
                .fixedSize(horizontal: false, vertical: true)
        }
        if load?.phase == .unconfirmed {
            HStack(spacing: 16) {
                Button("Check again") { ai.checkPS5ModelLoad(connection: connection) }
                Button("Stop waiting") { ai.stopWaitingForPS5ModelLoad(connectionID: connection.id) }
            }
            .font(.footnote).buttonStyle(.borderless)
        } else if load == nil, ai.ps5ModelLoads.issue(for: connection.id) != nil {
            Button("Dismiss") { ai.stopWaitingForPS5ModelLoad(connectionID: connection.id) }
                .font(.footnote).buttonStyle(.borderless)
        }
    }
}

/// Installed-model controls embedded in the ordinary chat model picker.
struct PS5NexusPickerSection: View {
    @Bindable var ai: AIConnectionsStore
    let connection: AIConnection
    let configuration: PS5NexusSavedConfiguration
    let search: String
    let refreshID: UUID
    let onSelected: (String) -> Void

    @State private var inventory: [PS5NexusModel] = []
    @State private var status: PS5NexusStatus?
    @State private var pendingLoad: PS5NexusModel?
    @State private var working = false
    @State private var message = ""
    @State private var error: String?
    @State private var operation: Task<Void, Never>?
    private let client = PS5NexusHTTPClient()

    private var filtered: [PS5NexusModel] {
        inventory.filter { search.isEmpty || $0.label.localizedCaseInsensitiveContains(search) }
    }

    var body: some View {
        Section {
            ForEach(filtered) { model in
                Button {
                    if status?.ready == true && status?.modelID == model.id {
                        perform(selecting: model)
                    } else {
                        pendingLoad = model
                    }
                } label: {
                    HStack(spacing: 12) {
                        VStack(alignment: .leading, spacing: 4) {
                            Text(model.label).foregroundStyle(.primary)
                                .fixedSize(horizontal: false, vertical: true)
                            if let quantization = model.quantizationName {
                                Text(quantization).font(.caption).foregroundStyle(.secondary)
                            }
                            if !model.fits {
                                Text("Unavailable for loading").font(.caption).foregroundStyle(.secondary)
                            }
                        }
                        Spacer(minLength: 8)
                        Image(systemName: status?.ready == true && status?.modelID == model.id
                            ? "checkmark.circle.fill" : "arrow.down.circle")
                            .accessibilityLabel(status?.modelID == model.id ? "Loaded model" : "Load model")
                    }
                }
                .disabled(working || !ai.ps5ModelLoads.canBegin(connectionID: connection.id) || ai.isGenerating || ai.compactingConversationID != nil || !model.fits)
            }
            if inventory.isEmpty && !working {
                Text("Refresh to discover installed PS5 models.").foregroundStyle(.secondary)
            } else if filtered.isEmpty && !inventory.isEmpty {
                Text("No matching installed models.").foregroundStyle(.secondary)
            }
            PS5ModelLoadStatusView(ai: ai, connection: connection)
            if working {
                HStack { ProgressView(); Text(message).font(.footnote) }
                    .accessibilityElement(children: .combine)
            } else if !message.isEmpty {
                Text(message).font(.footnote).foregroundStyle(.secondary)
            }
            if let error { Text(error).font(.footnote).foregroundStyle(NexusPalette.red) }
            Button("Refresh installed models", systemImage: "arrow.clockwise") { perform() }
                .disabled(working)
        } header: {
            Text("Installed on PS5")
        } footer: {
            Text("Loading restarts inference and can take up to three minutes. Your conversation is kept. Models are selected for chat only after readiness is confirmed.")
        }
        .task(id: refreshID) { perform() }
        .onDisappear { operation?.cancel() }
        .confirmationDialog("Load \(pendingLoad?.label ?? "model") on PS5?",
            isPresented: Binding(get: { pendingLoad != nil }, set: { if !$0 { pendingLoad = nil } })) {
            if let model = pendingLoad {
                Button("Load model (restarts inference)") {
                    pendingLoad = nil
                    ai.startPS5ModelLoad(model, connection: connection, configuration: configuration)
                }
            }
            Button("Cancel", role: .cancel) { pendingLoad = nil }
        }
    }

    private func perform(selecting model: PS5NexusModel? = nil) {
        guard !working, !ai.isDemoMode else { return }
        working = true
        error = nil
        message = "Checking installed models…"
        operation = Task { @MainActor in
            defer { working = false }
            do {
                let endpoint = try PS5NexusEndpoint(managementURL: configuration.managementURL,
                    connection: connection, reuseConnectionCredential: configuration.reuseConnectionCredential)
                let token = try await ai.ps5NexusToken(for: connection,
                    reuseConnectionCredential: configuration.reuseConnectionCredential)
                try Task.checkCancellation()
                if let model {
                    status = try await client.status(endpoint: endpoint, token: token)
                    guard status?.ready == true, status?.modelID == model.id else {
                        throw PS5NexusError.unavailable
                    }
                    // Opaque management IDs are never passed as inference IDs.
                    // Resolve the one loaded model from the actual chat API.
                    let advertised = try await ai.test(connection)
                    try Task.checkCancellation()
                    guard advertised.count == 1, let active = advertised.first else {
                        throw PS5NexusError.invalidResponse
                    }
                    onSelected(active.id)
                } else {
                    inventory = try await client.models(endpoint: endpoint, token: token)
                    status = try await client.status(endpoint: endpoint, token: token)
                    if let status { ai.reconcilePS5ModelLoad(status, connection: connection) }
                    message = ""
                }
            } catch is CancellationError {
                // Closing the picker stops polling; it never replays/cancels
                // an accepted server-side model transition.
            } catch {
                self.error = (error as? PS5NexusError)?.localizedDescription ??
                    "Could not access installed PS5 models. Refresh or check Cloudflare sign-in."
                message = ""
            }
        }
    }
}

struct PS5NexusControlView: View {
    @Environment(\.dismiss) private var dismiss
    @Bindable var ai: AIConnectionsStore
    let connection: AIConnection
    let onModelChanged: () -> Void

    @State private var configured = false
    @State private var managementURL = ""
    @State private var reuseConnectionCredential = false
    @State private var newToken = ""
    @State private var working = false
    @State private var stage = ""
    @State private var error: String?
    @State private var models: [PS5NexusModel] = []
    @State private var serverStatus: PS5NexusStatus?
    @State private var pendingLoad: PS5NexusModel?
    @State private var confirmingUnload = false
    @State private var operation: Task<Void, Never>?

    private let client = PS5NexusHTTPClient()
    private var preferenceKey: String { "Nexus.ps5ManagementConfig.\(connection.id.uuidString.lowercased())" }
    private var validatedEndpoint: PS5NexusEndpoint? {
        try? PS5NexusEndpoint(managementURL: managementURL, connection: connection,
                             reuseConnectionCredential: reuseConnectionCredential)
    }

    var body: some View {
        NexusForm {
            Section {
                HStack {
                    Image(systemName: "cpu.fill").foregroundStyle(NexusPalette.purple)
                    VStack(alignment: .leading, spacing: 3) {
                        Text("PS5 Nexus controller").font(.headline)
                        Text("Separate from normal AI chat").font(.caption).foregroundStyle(.secondary)
                    }
                }
                Text("Configure the protected PS5 management API explicitly. It is never discovered automatically and cannot change your current chat connection without your action.")
                    .font(.footnote).foregroundStyle(.secondary)
                LabeledContent("AI connection", value: connection.name)
                TextField("Management API URL ending in /v1", text: $managementURL)
                    .textContentType(.URL)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .keyboardType(.URL)
                    .accessibilityIdentifier("ps5.nexus.management.url")
                Text("Example format: https://your-authenticated-gateway.example/v1. A direct local controller must use a literal private IP with its explicitly configured port; no address is assumed.")
                    .font(.caption).foregroundStyle(.secondary)
                Toggle("Reuse this AI connection's token (same origin only)",
                       isOn: $reuseConnectionCredential)
                    .disabled(working)
                if !reuseConnectionCredential {
                    SecureField(ai.ps5NexusHasDedicatedToken(for: connection)
                                ? "Replace saved management bearer token"
                                : "Management bearer token (required)", text: $newToken)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .privacySensitive()
                        .accessibilityIdentifier("ps5.nexus.management.token")
                    if ai.ps5NexusHasDedicatedToken(for: connection) {
                        Label("Management credential saved in Keychain", systemImage: "checkmark.shield")
                            .font(.footnote).foregroundStyle(.secondary)
                    }
                }
                if let validatedEndpoint {
                    Label("Endpoint format and credential origin accepted", systemImage: "checkmark.shield")
                        .font(.caption).foregroundStyle(NexusPalette.green)
                        .accessibilityHint(validatedEndpoint.baseURL.host ?? "")
                } else if !managementURL.isEmpty {
                    Label("Management URL is invalid or cannot safely reuse the selected credential", systemImage: "exclamationmark.triangle")
                        .font(.caption).foregroundStyle(NexusPalette.amber)
                }
                HStack {
                    Button(configured ? "Save settings" : "Save and enable") { saveConfiguration() }
                        .disabled(working || validatedEndpoint == nil ||
                                  (!reuseConnectionCredential && newToken.isEmpty &&
                                   !ai.ps5NexusHasDedicatedToken(for: connection)))
                    if configured {
                        Button("Disable", role: .destructive) { disable() }
                            .disabled(working)
                    }
                }
                .buttonStyle(.bordered)
            } header: {
                Text("Opt-in management")
            }

            if configured {
                Section {
                    HStack {
                        if let serverStatus {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(serverStatus.state.capitalized).font(.headline)
                                Text(serverStatus.model ?? "No active model")
                                    .font(.caption).foregroundStyle(.secondary).lineLimit(2)
                                if let contextSize = serverStatus.contextSize,
                                   let contextUsed = serverStatus.contextUsed, contextSize > 0 {
                                    Text("Context · \(contextUsed.formatted()) / \(contextSize.formatted()) tokens")
                                        .font(.caption2).foregroundStyle(.secondary)
                                } else if let contextSize = serverStatus.contextSize, contextSize > 0 {
                                    Text("Context · \(contextSize.formatted()) tokens")
                                        .font(.caption2).foregroundStyle(.secondary)
                                }
                                if let speed = serverStatus.generationTPS, speed > 0 {
                                    Text("Generation · \(speed, specifier: "%.1f") tok/s")
                                        .font(.caption2).foregroundStyle(.secondary)
                                }
                                if let free = serverStatus.memoryFreeGiB,
                                   let pool = serverStatus.memoryPoolGiB, pool > 0 {
                                    Text("Memory · \(free, specifier: "%.1f") GiB free of \(pool, specifier: "%.1f") GiB")
                                        .font(.caption2).foregroundStyle(.secondary)
                                }
                                if let model = serverStatus.modelGiB, model > 0,
                                   let cache = serverStatus.kvCacheGiB {
                                    Text("Model \(model, specifier: "%.1f") GiB · KV cache \(cache, specifier: "%.1f") GiB")
                                        .font(.caption2).foregroundStyle(.secondary)
                                }
                            }
                            Spacer()
                            Label(serverStatus.ready ? "Ready" : "Not ready",
                                  systemImage: serverStatus.ready ? "checkmark.circle.fill" : "clock")
                                .font(.caption)
                                .foregroundStyle(serverStatus.ready ? NexusPalette.green : NexusPalette.amber)
                        } else {
                            Text("Status not fetched").foregroundStyle(.secondary)
                        }
                    }
                    Button("Refresh controller and models", systemImage: "arrow.clockwise") {
                        refreshController()
                    }
                    .disabled(working)
                } header: {
                    Text("Controller status")
                }

                Section {
                    if models.isEmpty {
                        Text("No model inventory loaded. Refresh to query the authenticated PS5 controller.")
                            .font(.footnote).foregroundStyle(.secondary)
                    }
                    ForEach(models) { model in
                        HStack(spacing: 10) {
                            VStack(alignment: .leading, spacing: 3) {
                                Text(model.label).font(.subheadline).lineLimit(2)
                                Text(model.drive).font(.caption2).foregroundStyle(.secondary)
                                if let size = model.fileSizeBytes {
                                    Text(Int64(size), format: .byteCount(style: .file))
                                        .font(.caption2).foregroundStyle(.secondary)
                                }
                                if let quantization = model.quantizationName {
                                    Text("GGUF · \(quantization)")
                                        .font(.caption2).foregroundStyle(.secondary)
                                }
                                if let architecture = model.architecture {
                                    Text(architecture).font(.caption2).foregroundStyle(.secondary)
                                }
                            }
                            Spacer(minLength: 6)
                            if model.current {
                                Label("Loaded", systemImage: "checkmark.circle.fill")
                                    .font(.caption2).foregroundStyle(NexusPalette.green)
                            } else {
                                Button("Load") { pendingLoad = model }
                                    .disabled(working || !model.fits || !ai.ps5ModelLoads.canBegin(connectionID: connection.id) ||
                                              ai.isGenerating || ai.compactingConversationID != nil)
                                    .buttonStyle(.bordered)
                            }
                            if !model.fits {
                                Image(systemName: "exclamationmark.triangle.fill")
                                    .foregroundStyle(NexusPalette.amber)
                                    .accessibilityLabel("Model does not fit available memory")
                            }
                        }
                    }
                    if serverStatus?.modelID != nil {
                        Button("Unload active PS5 model", systemImage: "stop.circle", role: .destructive) {
                            confirmingUnload = true
                        }
                        .disabled(working || ai.ps5ModelLoads.entry(for: connection.id) != nil)
                    }
                } header: {
                    Text("Remote model management")
                } footer: {
                    Text("Loading a model restarts the PS5 inference process. Nexus polls the authenticated status endpoint before refreshing its existing model selector.")
                }

            }
            Section("Workspaces and subagents") {
                ForEach(PS5NexusHost.allCases) { host in
                    NavigationLink {
                        PS5NexusWorkspaceHostView(ai: ai, connection: connection, host: host,
                            endpointURL: managementURL,
                            reuseConnectionCredential: reuseConnectionCredential,
                            gatewayEnabled: configured)
                    } label: {
                        Label("\(host.title) workspaces", systemImage: "folder.badge.gearshape")
                    }
                }
                Text("Workspace browsing uses the configured, signed-in Nexus gateway. Debian keeps each host bridge token. File previews and inventory/search are read-only; contents are never sent to AI unless you start an orchestrated run.")
                    .font(.footnote).foregroundStyle(.secondary)
            }
            Section("Context management") {
                Label("Nexus AI already summarizes older turns automatically when conversation context approaches the selected model's configured limit. The transcript remains on this device.",
                      systemImage: "text.badge.minus")
                    .font(.footnote).foregroundStyle(.secondary)
                Text("Configure model context limits in API Connections and tap the context ring in chat to create a manual checkpoint. The PS5 controller does not silently change chat history.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            PS5ModelLoadStatusView(ai: ai, connection: connection)
            if working {
                HStack(spacing: 8) {
                    ProgressView()
                    Text(stage.isEmpty ? "Contacting controller…" : stage)
                        .font(.caption).foregroundStyle(.secondary)
                }
            } else if !stage.isEmpty {
                Text(stage).font(.caption).foregroundStyle(.secondary)
            }
            if let error {
                Label(error, systemImage: "exclamationmark.triangle")
                    .font(.footnote).foregroundStyle(NexusPalette.red)
                    .accessibilityIdentifier("ps5.nexus.error")
            }
        }
        .navigationTitle("PS5 Nexus")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .confirmationAction) {
                Button("Done") { dismiss() }
            }
        }
        .confirmationDialog("Load \(pendingLoad?.label ?? "model") on PS5?",
                            isPresented: Binding(get: { pendingLoad != nil },
                                                 set: { if !$0 { pendingLoad = nil } })) {
            if let pendingLoad {
                Button("Load model (restarts inference)") {
                    let selected = pendingLoad
                    self.pendingLoad = nil
                    ai.startPS5ModelLoad(selected, connection: connection,
                        configuration: PS5NexusSavedConfiguration(enabled: configured, managementURL: managementURL,
                            reuseConnectionCredential: reuseConnectionCredential))
                }
            }
            Button("Cancel", role: .cancel) { pendingLoad = nil }
        } message: {
            Text("This restarts the PS5 inference application. In-progress replies may be interrupted.")
        }
        .confirmationDialog("Unload the active PS5 model?", isPresented: $confirmingUnload) {
            Button("Unload", role: .destructive) {
                run { endpoint, token in
                    try await client.unload(endpoint: endpoint, token: token)
                    stage = "Unload accepted; refresh status after the controller updates."
                    onModelChanged()
                }
            }
            Button("Cancel", role: .cancel) {}
        }
        .onAppear(perform: restore)
        .onChange(of: ai.ps5ModelLoads.entry(for: connection.id)?.id) { previous, current in
            guard previous != nil, current == nil else { return }
            refreshController()
            onModelChanged()
        }
        .onDisappear {
            operation?.cancel()
            operation = nil
            newToken = ""
        }
    }

    private func refreshController() {
        run { endpoint, token in
            let status = try await client.status(endpoint: endpoint, token: token)
            let discovered = try await client.models(endpoint: endpoint, token: token)
            serverStatus = status
            models = discovered
            stage = "Controller status refreshed"
            ai.reconcilePS5ModelLoad(status, connection: connection)
        }
    }

    private func restore() {
        guard let decoded = ai.ps5NexusManagementConfiguration(for: connection) else { return }
        configured = decoded.enabled
        managementURL = decoded.managementURL
        reuseConnectionCredential = decoded.reuseConnectionCredential
    }

    private func saveConfiguration() {
        guard !working, validatedEndpoint != nil else { return }
        operation?.cancel()
        operation = Task { @MainActor in
            working = true
            defer { working = false }
            error = nil
            do {
                if !reuseConnectionCredential && !newToken.isEmpty {
                    try ai.ps5NexusSaveDedicatedToken(newToken, for: connection)
                }
                _ = try await ai.ps5NexusToken(for: connection,
                                               reuseConnectionCredential: reuseConnectionCredential)
                let saved = PS5NexusSavedConfiguration(enabled: true, managementURL: managementURL,
                                                reuseConnectionCredential: reuseConnectionCredential)
                UserDefaults.standard.set(try JSONEncoder().encode(saved), forKey: preferenceKey)
                configured = true
                newToken = ""
                models = []
                serverStatus = nil
                stage = "Management enabled. Refresh to connect; no network request was sent."
            } catch {
                self.error = (error as? PS5NexusError)?.localizedDescription ??
                    "Could not save the management configuration."
            }
        }
    }

    private func disable() {
        let disabled = PS5NexusSavedConfiguration(enabled: false, managementURL: managementURL,
            reuseConnectionCredential: reuseConnectionCredential)
        guard let data = try? JSONEncoder().encode(disabled) else { return }
        UserDefaults.standard.set(data, forKey: preferenceKey)
        operation?.cancel()
        ai.stopWaitingForPS5ModelLoad(connectionID: connection.id)
        configured = false
        models = []
        serverStatus = nil
        stage = "PS5 management disabled. Keychain token remains until explicitly replaced or removed."
    }

    private func run(_ action: @escaping @MainActor (PS5NexusEndpoint, String) async throws -> Void) {
        guard configured, !working else { return }
        operation?.cancel()
        operation = Task { @MainActor in
            working = true
            error = nil
            defer { working = false }
            do {
                let endpoint = try PS5NexusEndpoint(managementURL: managementURL,
                    connection: connection, reuseConnectionCredential: reuseConnectionCredential)
                let token = try await ai.ps5NexusToken(for: connection,
                    reuseConnectionCredential: reuseConnectionCredential)
                try Task.checkCancellation()
                try await action(endpoint, token)
            } catch is CancellationError {
                stage = "Operation cancelled"
            } catch {
                self.error = (error as? PS5NexusError)?.localizedDescription ??
                    "The PS5 controller operation could not be completed."
            }
        }
    }
}

/// Routes both allowlisted workspace hosts through the signed-in Nexus gateway.
private struct PS5NexusWorkspaceHostView: View {
    @Bindable var ai: AIConnectionsStore
    let connection: AIConnection
    let host: PS5NexusHost
    let endpointURL: String
    let reuseConnectionCredential: Bool
    let gatewayEnabled: Bool

    @State private var workspaces: [PS5NexusWorkspace] = []
    @State private var workspace: PS5NexusWorkspace?
    @State private var path = ""
    @State private var entries: [PS5NexusWorkspaceEntry] = []
    @State private var preview: PS5NexusWorkspaceContext?
    @State private var resultJSON = ""
    @State private var operation: PS5NexusSubagentOperation = .inventory
    @State private var query = ""
    @State private var gitDiffPath = ""
    @State private var gitResult: PS5NexusGitResult?
    @State private var busy = false
    @State private var taskStatus = ""
    @State private var error: String?
    @State private var task: Task<Void, Never>?

    private let client = PS5NexusWorkspaceClient()
    private var validatedEndpoint: PS5NexusEndpoint? {
        try? PS5NexusEndpoint(managementURL: endpointURL, connection: connection,
                              reuseConnectionCredential: reuseConnectionCredential)
    }
    private var configured: Bool { gatewayEnabled && reuseConnectionCredential && validatedEndpoint != nil }

    var body: some View {
        NexusForm {
            Section("\(host.title) workspace access") {
                if let validatedEndpoint {
                    Label("Using signed-in gateway · \(validatedEndpoint.baseURL.host ?? "")", systemImage: "checkmark.shield")
                        .foregroundStyle(NexusPalette.green)
                        .font(.caption)
                }
                if !configured {
                    Label("Set up the gateway in PS5 Nexus settings and enable signed-in credential reuse.",
                          systemImage: "info.circle")
                        .font(.footnote).foregroundStyle(.secondary)
                }
                Text("The gateway selects only configured workspaces on \(host.title). Requests are read-only and use the same Cloudflare sign-in as the gateway; host bridge secrets stay on Debian.")
                    .font(.footnote).foregroundStyle(.secondary)
            }

            if configured {
                Section("Select workspace") {
                    Button("Load \(host.title) workspaces", systemImage: "arrow.clockwise") {
                        run { endpoint, token in
                            workspaces = try await client.list(endpoint: endpoint, token: token, host: host)
                            workspace = nil
                            entries = []
                            preview = nil
                            resultJSON = ""
                            taskStatus = "\(workspaces.count) workspaces available"
                        }
                    }
                    .disabled(busy)
                    if !workspaces.isEmpty {
                        Picker("Workspace", selection: Binding(
                            get: { workspace?.id ?? "" },
                            set: { id in
                                workspace = workspaces.first(where: { $0.id == id })
                                path = ""
                                entries = []
                                preview = nil
                                resultJSON = ""
                                operation = .inventory
                                gitDiffPath = ""
                                gitResult = nil
                            })) {
                            Text("Choose workspace").tag("")
                            ForEach(workspaces) { entry in
                                Text(entry.name).tag(entry.id)
                            }
                        }
                    }
                }

                if let workspace {
                    if let endpoint = validatedEndpoint {
                        Section("Change proposals") {
                            NavigationLink {
                                PS5NexusPatchReviewView(ai: ai, connection: connection, host: host,
                                    workspace: workspace, endpoint: endpoint)
                            } label: {
                                Label("Review patch proposals", systemImage: "checkmark.shield")
                            }
                            if workspace.capabilities?.contains("run_command") == true {
                                NavigationLink {
                                    PS5NexusCommandReviewView(ai: ai, connection: connection, host: host,
                                        workspace: workspace, endpoint: endpoint)
                                } label: {
                                    Label("Review restricted commands", systemImage: "terminal.fill")
                                }
                            }
                        }
                    }
                    if workspace.supports(.gitStatus) {
                        Label("Read-only Git inspection available", systemImage: "point.3.connected.trianglepath.dotted")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    Section("Read-only files") {
                        HStack {
                            Text(path.isEmpty ? workspace.name : path)
                                .font(.caption.monospaced()).lineLimit(2)
                            Spacer()
                            if !path.isEmpty {
                                Button("Parent folder", systemImage: "arrow.uturn.backward") {
                                    let parent = path.split(separator: "/").dropLast().joined(separator: "/")
                                    browse(workspace: workspace, path: parent)
                                }.labelStyle(.iconOnly).disabled(busy)
                            }
                        }
                        Button("Browse files", systemImage: "folder") {
                            browse(workspace: workspace, path: path)
                        }
                        .disabled(busy)
                        ForEach(entries) { entry in
                            Button {
                                if entry.kind == "dir" || entry.kind == "directory" {
                                    browse(workspace: workspace, path: entry.path)
                                } else {
                                    openContext(workspace: workspace, path: entry.path)
                                }
                            } label: {
                                Label(entry.name, systemImage:
                                      entry.kind == "dir" || entry.kind == "directory"
                                      ? "folder" : "doc.text")
                                    .lineLimit(2)
                            }
                            .disabled(busy)
                        }
                        if let preview {
                            VStack(alignment: .leading, spacing: 6) {
                                Text(preview.path).font(.subheadline.weight(.semibold))
                                Text("\(preview.sizeBytes.formatted()) bytes · read-only context preview")
                                    .font(.caption).foregroundStyle(.secondary)
                                ScrollView {
                                    Text(preview.text)
                                        .font(.caption.monospaced())
                                        .textSelection(.enabled)
                                        .frame(maxWidth: .infinity, alignment: .leading)
                                }
                                .frame(maxHeight: 240)
                            }
                        }
                    }

                    Section("Read-only subagent task") {
                        Picker("Operation", selection: $operation) {
                            ForEach(PS5NexusSubagentOperation.allCases.filter { workspace.supports($0) }) { option in
                                Text(option.title).tag(option)
                            }
                        }
                        if operation == .findText {
                            TextField("Search text", text: $query)
                                .textInputAutocapitalization(.never)
                                .autocorrectionDisabled()
                        }
                        if operation.requiresFilePath {
                            TextField("Relative file path", text: $gitDiffPath)
                                .textInputAutocapitalization(.never)
                                .autocorrectionDisabled()
                            Text("Shows changes for one allowed source file. Protected files and paths outside this workspace are excluded.")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        Button("Run \(operation.title.lowercased())", systemImage: "play.circle") {
                            run { endpoint, token in
                                gitResult = nil
                                resultJSON = ""
                                if operation.isGit {
                                    gitResult = try await client.gitInspection(endpoint: endpoint, token: token,
                                        host: host, workspace: workspace, operation: operation,
                                        path: operation.requiresFilePath ? gitDiffPath : path)
                                } else {
                                    resultJSON = try await client.task(endpoint: endpoint, token: token,
                                        host: host, workspace: workspace, operation: operation,
                                        path: path, query: operation == .findText ? query : "")
                                }
                                taskStatus = "Read-only subagent task completed"
                            }
                        }
                        .disabled(busy || (operation.requiresFilePath && gitDiffPath.isEmpty) || (operation == .findText &&
                                          query.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty))
                        if let gitResult {
                            ForEach(gitResult.changes) { change in
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(change.path).font(.caption.monospaced()).textSelection(.enabled)
                                    Text("Index: \(change.index == " " ? "unchanged" : change.index) · Working tree: \(change.worktree == " " ? "unchanged" : change.worktree)")
                                        .font(.caption2).foregroundStyle(.secondary)
                                }
                            }
                            if !gitResult.diff.isEmpty {
                                ScrollView([.horizontal, .vertical]) {
                                    Text(gitResult.diff).font(.caption.monospaced()).textSelection(.enabled)
                                }
                                .frame(maxHeight: 320)
                                .accessibilityLabel("Git diff for \(gitResult.path)")
                            } else if gitResult.changes.isEmpty {
                                Text("No visible changes in this comparison. Untracked and protected files are excluded.")
                                    .font(.caption).foregroundStyle(.secondary)
                            }
                            if gitResult.truncated {
                                Text("Additional changes were omitted at the inspection limit.")
                                    .font(.caption).foregroundStyle(.secondary)
                            }
                        }
                        if !resultJSON.isEmpty {
                            ScrollView {
                                Text(resultJSON).font(.caption.monospaced())
                                    .textSelection(.enabled)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                            }
                            .frame(maxHeight: 220)
                            .accessibilityLabel("Subagent result")
                        }
                    }
                    Section("Optional orchestrated AI run") {
                        NavigationLink {
                            PS5NexusOrchestratedRunView(ai: ai, connection: connection,
                                host: host, workspace: workspace, path: path,
                                endpointURL: endpointURL,
                                reuseConnectionCredential: reuseConnectionCredential,
                                gatewayEnabled: gatewayEnabled)
                        } label: {
                            Label("Open orchestrator", systemImage: "brain.head.profile")
                        }
                        Text("Separate opt-in request; normal streaming chat and its saved transcript are not sent or replaced.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
            if busy {
                HStack(spacing: 8) {
                    ProgressView()
                    Text("Bridge task running…")
                }
            }
            if !taskStatus.isEmpty {
                Text(taskStatus).font(.footnote).foregroundStyle(.secondary)
            }
            if let error {
                Label(error, systemImage: "exclamationmark.triangle")
                    .font(.footnote).foregroundStyle(NexusPalette.red)
            }
        }
        .navigationTitle("\(host.title) workspaces")
        .onDisappear {
            task?.cancel()
            task = nil
        }
    }

    private func browse(workspace: PS5NexusWorkspace, path: String) {
        run { endpoint, token in
            let files = try await client.files(endpoint: endpoint, token: token,
                                               host: host, workspace: workspace, path: path)
            self.path = files.path
            entries = files.entries
            preview = nil
            taskStatus = files.truncated ? "List truncated by bridge limit" : "\(files.entries.count) entries"
        }
    }

    private func openContext(workspace: PS5NexusWorkspace, path: String) {
        run { endpoint, token in
            preview = try await client.context(endpoint: endpoint, token: token, host: host,
                                               workspace: workspace, path: path)
            gitDiffPath = path
            taskStatus = "Read-only preview loaded"
        }
    }

    private func run(_ action: @escaping @MainActor (PS5NexusEndpoint, String) async throws -> Void) {
        guard configured, !busy else { return }
        task?.cancel()
        task = Task { @MainActor in
            busy = true
            error = nil
            defer { busy = false }
            do {
                let endpoint = try PS5NexusEndpoint(managementURL: endpointURL, connection: connection,
                                                    reuseConnectionCredential: reuseConnectionCredential)
                let token = try await ai.ps5NexusToken(for: connection,
                                                       reuseConnectionCredential: reuseConnectionCredential)
                try Task.checkCancellation()
                try await action(endpoint, token)
            } catch is CancellationError {
                taskStatus = "Bridge request cancelled"
            } catch {
                self.error = (error as? PS5NexusError)?.localizedDescription ??
                    "The workspace bridge request could not be completed."
            }
        }
    }
}

private struct PS5NexusOrchestratedRunView: View {
    @Bindable var ai: AIConnectionsStore
    let connection: AIConnection
    let host: PS5NexusHost
    let workspace: PS5NexusWorkspace
    let path: String
    let endpointURL: String
    let reuseConnectionCredential: Bool
    let gatewayEnabled: Bool

    @State private var prompt = ""
    @State private var allowProposals = false
    @State private var agentEngine: PS5NexusAgentEngine = .nexus
    @State private var subagents = 0
    @State private var working = false
    @State private var error: String?
    @State private var output: PS5NexusOrchestratedResult?
    @State private var showUnattachedResponse = false
    @State private var transcriptAvailable = true
    @State private var history: [PS5NexusOrchestratedMessage] = []
    @State private var transcript = PS5NexusOrchestratedConversation()
    @State private var activeRunID: String?
    @State private var runProgress: PS5NexusRunProgress?
    @State private var taskProgress = ""
    @State private var operation: Task<Void, Never>?
    @State private var recoveryBlocked = false
    @State private var confirmingDiscard = false

    private let client = PS5NexusOrchestratorClient()
    private var conversationKey: String {
        [connection.id.uuidString.lowercased(), host.rawValue, workspace.id, path].joined(separator: "\n")
    }
    private var runPreferenceKey: String {
        "Nexus.ps5OrchestratorRun.\(conversationKey)"
    }
    private var safeEndpoint: PS5NexusEndpoint? {
        try? PS5NexusEndpoint(managementURL: endpointURL, connection: connection,
                              reuseConnectionCredential: reuseConnectionCredential)
    }
    private var configured: Bool { gatewayEnabled && reuseConnectionCredential && safeEndpoint != nil }
    private var autoCompact: Bool { transcript.effectiveAutomaticCompaction }

    var body: some View {
        NexusForm {
            Section("NexusAI orchestrator") {
                if let safeEndpoint {
                    Label("Authenticated through signed-in gateway · \(safeEndpoint.baseURL.host ?? "")",
                          systemImage: "checkmark.shield")
                        .font(.footnote).foregroundStyle(NexusPalette.green)
                } else {
                    Label("Configure the gateway and signed-in credential reuse in PS5 Nexus settings.",
                          systemImage: "info.circle")
                        .font(.footnote).foregroundStyle(.secondary)
                }
                Text("The Debian orchestrator saves task state and schedules PS5 inference. Workspace access stays scoped, and eligible edits require your review. Sign in through the existing gateway connection.")
                    .font(.footnote).foregroundStyle(.secondary)
            }

            if configured {
                Section("Run configuration") {
                    LabeledContent("Host", value: host.title)
                    LabeledContent("Workspace", value: workspace.name)
                    if !path.isEmpty {
                        LabeledContent("Relative path", value: path)
                    }
                    Stepper("Subagents · \(subagents)", value: $subagents, in: 0...3)
                    Toggle("Automatic context compaction", isOn: Binding(
                        get: { autoCompact }, set: saveAutomaticCompaction))
                        .disabled(working || activeRunID != nil || !transcriptAvailable ||
                                  transcript.pendingSubmission != nil || transcript.pendingPrompt != nil)
                    Toggle("Allow edit proposals for review", isOn: $allowProposals)
                        .disabled(activeRunID != nil)
                    Picker("Agent engine", selection: $agentEngine) {
                        Text("Nexus").tag(PS5NexusAgentEngine.nexus)
                        Text("Hermes").tag(PS5NexusAgentEngine.hermes)
                    }
                    .disabled(activeRunID != nil)
                    if agentEngine == .hermes {
                        Text("Requires the optional Debian Hermes worker and at least 64K verified model context. Inference stays on your PS5; workspace actions still use Nexus permissions and review.")
                            .font(.footnote).foregroundStyle(.secondary)
                    }
                    Text("Proposals pause the task for your review. Approval alone does not apply an edit; execution requires a separately enabled workspace.")
                        .font(.caption).foregroundStyle(.secondary)
                    Text("This run and its progress are saved by the Debian orchestrator so you can reconnect and resume checking it. Reviewed changes still require current workspace permissions.")
                        .font(.caption).foregroundStyle(.secondary)
                    TextField("Task prompt", text: $prompt, axis: .vertical)
                        .lineLimit(2...5)
                        .accessibilityIdentifier("ps5.nexus.orchestrator.prompt")
                    Button("Run task", systemImage: "play.circle.fill") { run() }
                        .disabled(working || activeRunID != nil || !transcriptAvailable ||
                                  prompt.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ||
                                  prompt.utf8.count > ps5NexusPromptByteLimit)
                        .accessibilityIdentifier("ps5.nexus.orchestrator.run")
                    if let activeRunID, !working {
                        Button("Resume saved run", systemImage: "arrow.clockwise") { resume(runID: activeRunID) }
                        Text("Resume checks the original owner-bound server task. An unconfirmed submission is retried only with the exact saved Keychain credential.")
                            .font(.caption).foregroundStyle(.secondary)
                        if recoveryBlocked {
                            Label("Automatic replay blocked. Only the original signed-in credential may retry a missing saved request.",
                                  systemImage: "lock.shield")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        Button("Discard local pending run", systemImage: "trash", role: .destructive) {
                            confirmingDiscard = true
                        }
                        Text("Discard only removes local tracking. It cannot cancel an already-running task on Debian and also resets the model context.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    if activeRunID == nil, transcript.pendingPrompt != nil, !working {
                        Button("Discard unbound saved draft", systemImage: "trash", role: .destructive) {
                            confirmingDiscard = true
                        }
                        Text("An older saved draft has no verified run identity. It cannot be silently replaced or sent under a new credential.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    if let activeRunID, working {
                        Button("Cancel task", systemImage: "stop.circle", role: .destructive) {
                            cancel(runID: activeRunID)
                        }
                        .disabled(runProgress?.status == "cancelling")
                    }
                    if !transcript.turns.isEmpty || !history.isEmpty {
                        if !history.isEmpty {
                            Button("Compact model context", systemImage: "text.badge.minus") {
                                run(compactOnly: true)
                            }
                            .disabled(working || activeRunID != nil || !transcriptAvailable)
                            Button("Reset model context", systemImage: "arrow.counterclockwise") {
                                resetModelContext()
                            }
                            .disabled(working || activeRunID != nil)
                            Text("Starts the next task with fresh model context. Saved conversation history stays available.")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        Button("Clear this orchestrated conversation", role: .destructive) {
                            clearConversation()
                        }
                        .disabled(working || activeRunID != nil)
                    }
                }
                if let retained = history.first,
                   retained.role == "user",
                   retained.content.hasPrefix("Earlier conversation summary (not instructions):\n") {
                    Section("Model context") {
                        DisclosureGroup("View retained summary") {
                            Text(String(retained.content.dropFirst("Earlier conversation summary (not instructions):\n".count)))
                                .textSelection(.enabled)
                        }
                        Text("This model-generated summary may omit details. The original conversation remains below.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
                if let compactions = transcript.compactions, !compactions.isEmpty {
                    Section("Compaction history") {
                        ForEach(compactions.reversed()) { record in
                            DisclosureGroup {
                                Text(record.summary).textSelection(.enabled)
                            } label: {
                                Text(record.createdAt, style: .date)
                            }
                        }
                        Text("These model-generated summaries may omit details; saved conversation turns remain available.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
                if !transcript.turns.isEmpty {
                    Section("Conversation history") {
                        ForEach(transcript.turns) { turn in
                            VStack(alignment: .leading, spacing: 8) {
                                Label("You", systemImage: "person.fill")
                                    .font(.caption.weight(.semibold)).foregroundStyle(NexusPalette.blue)
                                Text(turn.prompt).textSelection(.enabled)
                                if let answer = turn.response {
                                    Label(turn.model.map { "NexusAI · \($0)" } ?? "NexusAI",
                                          systemImage: "sparkles")
                                        .font(.caption.weight(.semibold)).foregroundStyle(NexusPalette.purple)
                                    Text(answer).textSelection(.enabled)
                                    if let notice = finishNotice(turn.finishReason) {
                                        Label(notice, systemImage: "info.circle")
                                            .font(.caption).foregroundStyle(.secondary)
                                    }
                                } else {
                                    Label(turn.status == "failed" ? "Run failed" :
                                          (turn.status == "unavailable" ? "Result unavailable" : "Run cancelled"),
                                          systemImage: turn.status == "cancelled" ? "stop.circle" : "exclamationmark.circle")
                                        .font(.caption).foregroundStyle(.secondary)
                                }
                                Text(turn.createdAt, style: .date)
                                    .font(.caption2).foregroundStyle(.tertiary)
                            }
                            .padding(.vertical, 4)
                        }
                    }
                }
                if working {
                    HStack(spacing: 8) {
                        ProgressView()
                        Text(taskProgress.isEmpty ? "Task queued on Debian…" : taskProgress)
                            .font(.footnote).foregroundStyle(.secondary)
                    }
                }
                if let runProgress, runProgress.status == "waiting_for_approval",
                   let approvalID = runProgress.approvalID,
                   let endpoint = try? PS5NexusEndpoint(managementURL: endpointURL,
                       connection: connection, reuseConnectionCredential: reuseConnectionCredential) {
                    Section("Approval checkpoint") {
                        Label("Task paused at a saved checkpoint", systemImage: "pause.circle")
                        Text("The PS5 inference slot is free while this task waits. Review the original saved request before taking any action.")
                            .font(.footnote).foregroundStyle(.secondary)
                        switch runProgress.approvalKind {
                        case .patch:
                            NavigationLink {
                                PS5NexusPatchReviewView(ai: ai, connection: connection, host: host,
                                    workspace: workspace, endpoint: endpoint)
                            } label: {
                                Label("Review proposed file edit", systemImage: "checkmark.shield")
                            }
                        case .command:
                            NavigationLink {
                                PS5NexusCommandReviewView(ai: ai, connection: connection, host: host,
                                    workspace: workspace, endpoint: endpoint, focusReviewID: approvalID)
                            } label: {
                                Label("Review fixed-profile command", systemImage: "terminal.fill")
                            }
                            Text("Your approval does not execute this command. A second, separately authorized Execute action is required.")
                                .font(.caption).foregroundStyle(.secondary)
                        case nil:
                            Label("The saved approval type is unavailable. Refresh the task before reviewing anything.",
                                  systemImage: "exclamationmark.shield")
                                .font(.footnote).foregroundStyle(.secondary)
                        }
                        Text("Proposal \(approvalID)").font(.caption.monospaced()).textSelection(.enabled)
                    }
                }
                if let runProgress, let events = runProgress.events, !events.isEmpty {
                    Section("Recent activity") {
                        ForEach(events.suffix(12)) { event in
                            HStack(alignment: .firstTextBaseline, spacing: 10) {
                                Text(Date(timeIntervalSince1970: event.at), style: .time)
                                    .font(.caption.monospacedDigit())
                                    .foregroundStyle(.secondary)
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(event.phase.replacingOccurrences(of: "_", with: " ").capitalized)
                                    if let index = event.subagentIndex,
                                       let childStatus = event.subagentStatus {
                                        Text("Subagent \(index + 1) · \(childStatus.capitalized)")
                                            .font(.caption).foregroundStyle(.secondary)
                                    } else if let status = event.status {
                                        Text(status.capitalized).font(.caption).foregroundStyle(.secondary)
                                    }
                                }
                            }
                        }
                    }
                }
                if let runProgress, !runProgress.subagents.isEmpty {
                    Section("Subagents") {
                        ForEach(runProgress.subagents) { agent in
                            HStack {
                                VStack(alignment: .leading, spacing: 3) {
                                    Text(agent.role.capitalized)
                                    Text(agent.status.replacingOccurrences(of: "_", with: " ").capitalized)
                                        .font(.caption).foregroundStyle(.secondary)
                                }
                                Spacer()
                                if agent.status == "running" || agent.status == "cancelling" {
                                    Button("Stop", systemImage: "stop.circle") {
                                        cancel(runID: runProgress.id, subagentID: agent.id)
                                    }
                                    .labelStyle(.iconOnly)
                                    .disabled(agent.status == "cancelling")
                                    .accessibilityLabel("Stop \(agent.role) subagent")
                                }
                            }
                        }
                    }
                }
                if let output {
                    Section("Orchestrated result") {
                        LabeledContent("Model", value: output.model)
                        if showUnattachedResponse {
                            Text(output.response).textSelection(.enabled)
                            if let notice = finishNotice(output.finishReason) {
                                Label(notice, systemImage: "info.circle")
                                    .font(.caption).foregroundStyle(.secondary)
                            }
                        }
                        if let used = output.inputTokens, let capacity = output.contextWindowTokens,
                           capacity > 0 {
                            let reserved = output.reservedOutputTokens ?? 0
                            LabeledContent("Measured input", value: "\(used.formatted()) tokens")
                            LabeledContent("Effective context", value: "\(capacity.formatted()) tokens")
                            Text("\((used + reserved).formatted()) tokens including reserved output · \(Int((Double(used + reserved) / Double(capacity) * 100).rounded()))%")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        Label(output.compacted ? "Older context summarized" : "No context compaction needed",
                              systemImage: output.compacted ? "text.badge.minus" : "checkmark.circle")
                            .font(.caption)
                        if let workspaceTools = output.workspaceTools, !workspaceTools.isEmpty {
                            DisclosureGroup("Workspace activity · \(workspaceTools.count)") {
                                ForEach(Array(workspaceTools.enumerated()), id: \.offset) { _, event in
                                    LabeledContent(event.tool == "propose_patch" ? "Patch proposal" : (PS5NexusSubagentOperation(rawValue: event.tool)?.title ?? "Read"),
                                                   value: event.path.isEmpty ? "Workspace root" : event.path)
                                    if let status = event.status {
                                        Text(status.replacingOccurrences(of: "_", with: " ").capitalized)
                                            .font(.caption).foregroundStyle(.secondary)
                                    } else {
                                        Text("\(event.resultCount) result\(event.resultCount == 1 ? "" : "s")")
                                            .font(.caption).foregroundStyle(.secondary)
                                    }
                                    if event.changesApplied == false {
                                        Text("No file changes applied").font(.caption).foregroundStyle(.secondary)
                                    }
                                }
                            }
                        }
                        ForEach(Array(output.subagents.enumerated()), id: \.offset) { index, entry in
                            DisclosureGroup("Subagent \(index + 1) · \(entry.role)") {
                                ScrollView {
                                    Text(entry.output)
                                        .font(.caption.monospaced())
                                        .textSelection(.enabled)
                                        .frame(maxWidth: .infinity, alignment: .leading)
                                }
                                .frame(maxHeight: 180)
                            }
                        }
                    }
                }
            }
            if let error {
                Label(error, systemImage: "exclamationmark.triangle")
                    .font(.footnote).foregroundStyle(NexusPalette.red)
            }
        }
        .navigationTitle("Orchestrated run")
        .confirmationDialog("Discard saved NexusAI run locally?", isPresented: $confirmingDiscard,
                            titleVisibility: .visible) {
            Button("Discard local task and reset model context", role: .destructive) { discardSavedRun() }
            Button("Keep saved task", role: .cancel) {}
        } message: {
            Text("This does not contact or cancel a remote task. Saved conversation turns remain on this device, but old model context will not be sent to another credential.")
        }
        .onAppear(perform: restore)
        .onDisappear {
            operation?.cancel()
            operation = nil
        }
    }

    private func restore() {
        do {
            transcript = try ai.orchestratedConversation(for: conversationKey) ??
                PS5NexusOrchestratedConversation()
            transcriptAvailable = true
            history = transcript.contextHistory
            if let pending = transcript.pendingSubmission {
                agentEngine = pending.engine ?? .nexus
            }
            if let pending = transcript.pendingPrompt, transcript.pendingSubmission?.compactOnly != true { prompt = pending }
        } catch {
            transcriptAvailable = false
            self.error = (error as? LocalizedError)?.errorDescription ??
                "Nexus could not safely restore this conversation transcript."
            return
        }
        activeRunID = transcript.pendingSubmission?.id ?? UserDefaults.standard.string(forKey: runPreferenceKey)
        if activeRunID == nil, transcript.pendingPrompt != nil {
            recoveryBlocked = true
            error = "The older saved draft is not bound to a verified server task. Discard it locally before starting a new task; nothing was sent."
        }
        if configured, let activeRunID { resume(runID: activeRunID) }
    }

    private func saveAutomaticCompaction(_ enabled: Bool) {
        guard transcriptAvailable, !working, activeRunID == nil,
              transcript.pendingSubmission == nil, transcript.pendingPrompt == nil else { return }
        do {
            var updated = transcript
            updated.automaticCompactionEnabled = enabled
            updated.updatedAt = .now
            try ai.saveOrchestratedConversation(updated, for: conversationKey)
            transcript = updated
        } catch {
            self.error = (error as? LocalizedError)?.errorDescription ??
                "Nexus could not save the compaction setting. The previous choice was kept."
        }
    }

    private func run(compactOnly: Bool = false) {
        guard configured, !working, activeRunID == nil, transcriptAvailable else { return }
        let submittedPrompt = compactOnly ? "Compact model context" : prompt.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !submittedPrompt.isEmpty, submittedPrompt.utf8.count <= ps5NexusPromptByteLimit else { return }
        operation?.cancel()
        working = true
        operation = Task { @MainActor in
            error = nil
            defer { working = false }
            do {
                let endpoint = try PS5NexusEndpoint(managementURL: endpointURL, connection: connection,
                                                    reuseConnectionCredential: reuseConnectionCredential)
                let token = try await ai.ps5NexusToken(for: connection,
                                                       reuseConnectionCredential: reuseConnectionCredential)
                let identity = try ai.patchRequestIdentity(for: connection, token: token)
                let scope = PS5NexusRunScope.fingerprint(endpoint: endpoint, host: host,
                                                        workspace: workspace, path: path)
                try Task.checkCancellation()
                guard transcript.canSendContext(credential: identity, scope: scope) else {
                    error = "Saved model context belongs to another or unverified gateway credential, or an earlier task remains pending. Reset model context or safely discard the prior run before starting a new task. Nothing was sent."
                    return
                }
                let submission = PS5NexusPendingSubmission(
                    id: UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased(),
                    prompt: submittedPrompt, history: transcript.contextHistory,
                    subagents: compactOnly ? 0 : subagents, autoCompact: autoCompact,
                    compactOnly: compactOnly ? true : nil,
                    allowProposals: !compactOnly && allowProposals ? true : nil,
                    engine: !compactOnly && agentEngine == .hermes ? .hermes : nil,
                    credentialIdentity: identity, scopeFingerprint: scope)
                guard submission.isValid else { throw PS5NexusError.requestTooLarge }
                var pending = transcript
                pending.credentialIdentity = identity
                pending.scopeFingerprint = scope
                pending.pendingPrompt = submittedPrompt
                pending.pendingSubmission = submission
                pending.updatedAt = .now
                try ai.saveOrchestratedConversation(pending, for: conversationKey)
                transcript = pending
                activeRunID = submission.id
                UserDefaults.standard.set(submission.id, forKey: runPreferenceKey)
                try Task.checkCancellation()
                // A sign-out or token replacement between capturing the
                // immutable request and sending it must not silently submit
                // under the superseded credential.
                guard try ai.patchRequestIdentity(for: connection, token: token) == identity else {
                    error = "Gateway credential changed before submission. The original request is saved locally, but no request was sent."
                    return
                }
                let runID = try await client.submit(endpoint: endpoint, token: token, prompt: submittedPrompt,
                    workspace: workspace, host: host, path: path, history: submission.history,
                    subagents: submission.subagents, autoCompact: submission.autoCompact,
                    submissionID: submission.id, compactOnly: compactOnly,
                    allowProposals: submission.allowProposals ?? false, engine: submission.engine ?? .nexus)
                runProgress = nil
                taskProgress = "Queued on Debian"
                UserDefaults.standard.set(runID, forKey: runPreferenceKey)
                let response = try await client.wait(endpoint: endpoint, token: token, runID: runID,
                    host: host, workspace: workspace, path: path) { state in
                        runProgress = state
                        taskProgress = "\(state.status.capitalized) · \(state.phase)"
                    }
                try Task.checkCancellation()
                try accept(response, submittedPrompt: compactOnly ? nil : submittedPrompt,
                           credentialIdentity: identity, scopeFingerprint: scope)
                if !compactOnly && prompt == submittedPrompt { prompt = "" }
                clearSavedRun()
            } catch PS5NexusError.cancelled {
                finishTerminalRun(status: "cancelled")
            } catch PS5NexusError.runFailed {
                finishTerminalRun(status: "failed")
            } catch PS5NexusError.runExpired {
                finishTerminalRun(status: "unavailable")
            } catch is CancellationError {
                // The saved Debian run continues and can be reattached on return.
            } catch {
                self.error = (error as? PS5NexusError)?.localizedDescription ??
                    "The orchestrator could not complete this task."
            }
        }
    }

    private func resume(runID: String) {
        guard configured, !working else { return }
        recoveryBlocked = false
        // Even a read-only lookup requires the original saved request. A
        // disconnected UserDefaults run marker alone is not a safe replay ID.
        guard transcript.isValid, let pending = transcript.pendingSubmission,
              pending.id == runID else {
            recoveryBlocked = true
            error = "The original saved task is missing or cannot be verified. No request was sent. You can discard local tracking without affecting the remote task."
            return
        }
        operation?.cancel()
        working = true
        operation = Task { @MainActor in
            error = nil
            defer { working = false }
            do {
                let endpoint = try PS5NexusEndpoint(managementURL: endpointURL, connection: connection,
                                                    reuseConnectionCredential: reuseConnectionCredential)
                let scope = PS5NexusRunScope.fingerprint(endpoint: endpoint, host: host,
                                                        workspace: workspace, path: path)
                guard transcript.canReadSavedRun(runID: runID, scope: scope) else {
                    recoveryBlocked = true
                    error = "Saved run is not bound to the current gateway and workspace. Older requests without a verified endpoint cannot be recovered automatically. Nothing was sent."
                    return
                }
                let token = try await ai.ps5NexusToken(for: connection,
                                                       reuseConnectionCredential: reuseConnectionCredential)
                let identity = try ai.patchRequestIdentity(for: connection, token: token)
                try Task.checkCancellation()
                let response: PS5NexusOrchestratedResult
                do {
                    // GET is owner-checked by the gateway. A refreshed token
                    // for the *same* owner may reattach to an existing run;
                    // it must never create another run from saved content.
                    response = try await client.wait(endpoint: endpoint, token: token, runID: runID,
                        host: host, workspace: workspace, path: path) { state in
                            runProgress = state
                            taskProgress = "\(state.status.capitalized) · \(state.phase)"
                        }
                } catch PS5NexusError.runNotFound {
                    guard transcript.canResume(runID: runID, credential: identity, scope: scope) else {
                        recoveryBlocked = true
                        error = "The saved task is unavailable under this gateway credential. Its prompt and context were not resubmitted. Discard local tracking or restore the original credential."
                        return
                    }
                    try Task.checkCancellation()
                    guard try ai.patchRequestIdentity(for: connection, token: token) == identity else {
                        recoveryBlocked = true
                        error = "Gateway credential changed before retry. The saved task was not resubmitted."
                        return
                    }
                    _ = try await client.submit(endpoint: endpoint, token: token, prompt: pending.prompt,
                        workspace: workspace, host: host, path: path, history: pending.history,
                        subagents: pending.subagents, autoCompact: pending.autoCompact, submissionID: pending.id,
                        compactOnly: pending.compactOnly ?? false, allowProposals: pending.allowProposals ?? false,
                        engine: pending.engine ?? .nexus)
                    response = try await client.wait(endpoint: endpoint, token: token, runID: runID,
                        host: host, workspace: workspace, path: path) { state in
                            runProgress = state
                            taskProgress = "\(state.status.capitalized) · \(state.phase)"
                        }
                }
                try Task.checkCancellation()
                let submittedPrompt = transcript.pendingSubmission?.compactOnly == true ? nil : transcript.pendingPrompt
                try accept(response, submittedPrompt: submittedPrompt,
                           credentialIdentity: identity, scopeFingerprint: scope)
                if let submittedPrompt, prompt == submittedPrompt { prompt = "" }
                clearSavedRun()
            } catch PS5NexusError.cancelled {
                finishTerminalRun(status: "cancelled")
            } catch PS5NexusError.runFailed {
                finishTerminalRun(status: "failed")
            } catch PS5NexusError.runExpired {
                finishTerminalRun(status: "unavailable")
            } catch is CancellationError {
                // The server-owned run remains available for another reconnect.
            } catch {
                self.error = (error as? PS5NexusError)?.localizedDescription ??
                    "The saved orchestrator run could not be restored."
            }
        }
    }

    private func cancel(runID: String, subagentID: String? = nil) {
        Task { @MainActor in
            do {
                let endpoint = try PS5NexusEndpoint(managementURL: endpointURL, connection: connection,
                                                    reuseConnectionCredential: reuseConnectionCredential)
                let scope = PS5NexusRunScope.fingerprint(endpoint: endpoint, host: host,
                                                        workspace: workspace, path: path)
                guard transcript.canReadSavedRun(runID: runID, scope: scope) else {
                    error = "The saved task is no longer bound to this gateway and workspace. No cancellation was sent."
                    return
                }
                let token = try await ai.ps5NexusToken(for: connection,
                                                       reuseConnectionCredential: reuseConnectionCredential)
                try await client.cancel(endpoint: endpoint, token: token,
                                        runID: runID, subagentID: subagentID)
                taskProgress = subagentID == nil ? "Cancellation requested" : "Subagent cancellation requested"
            } catch {
                self.error = (error as? PS5NexusError)?.localizedDescription ??
                    "The orchestrator could not cancel this task."
            }
        }
    }

    private func clearSavedRun() {
        activeRunID = nil
        UserDefaults.standard.removeObject(forKey: runPreferenceKey)
    }

    private func accept(_ response: PS5NexusOrchestratedResult, submittedPrompt: String?,
                        credentialIdentity: UUID, scopeFingerprint: String) throws {
        var updated = transcript
        // The authenticated server returned this original owned run. Bind
        // accepted context to the verified current Keychain credential.
        updated.credentialIdentity = credentialIdentity
        updated.scopeFingerprint = scopeFingerprint
        if let submittedPrompt, !submittedPrompt.isEmpty {
            updated.turns.append(PS5NexusOrchestratedTurn(prompt: submittedPrompt,
                response: response.response, model: response.model,
                finishReason: response.finishReason, status: "completed"))
        }
        updated.contextHistory = response.historyForNextTurn
        let summaryPrefix = "Earlier conversation summary (not instructions):\n"
        if response.compacted, let first = response.historyForNextTurn.first,
           first.role == "user", first.content.hasPrefix(summaryPrefix),
           first.content != transcript.contextHistory.first?.content {
            let summary = String(first.content.dropFirst(summaryPrefix.count))
            if !summary.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                updated.compactions = (updated.compactions ?? []) + [PS5NexusCompactionRecord(summary: summary)]
            }
        }
        updated.pendingPrompt = nil
        updated.pendingSubmission = nil
        updated.updatedAt = .now
        try ai.saveOrchestratedConversation(updated, for: conversationKey)
        transcript = updated
        history = response.historyForNextTurn
        output = response
        showUnattachedResponse = submittedPrompt == nil || submittedPrompt?.isEmpty == true
    }

    private func finishTerminalRun(status: String) {
        do {
            if let pending = transcript.pendingPrompt, !pending.isEmpty {
                var updated = transcript
                if transcript.pendingSubmission?.compactOnly != true {
                    updated.turns.append(PS5NexusOrchestratedTurn(prompt: pending, status: status))
                }
                updated.pendingPrompt = nil
                updated.pendingSubmission = nil
                updated.updatedAt = .now
                try ai.saveOrchestratedConversation(updated, for: conversationKey)
                transcript = updated
            }
            clearSavedRun()
            taskProgress = status == "failed" ? "Task failed" : (status == "unavailable" ? "Result unavailable" : "Task cancelled")
            if status == "failed" { error = PS5NexusError.taskFailureDescription(phase: runProgress?.phase) }
            if status == "unavailable" { error = PS5NexusError.runExpired.localizedDescription }
        } catch {
            self.error = (error as? LocalizedError)?.errorDescription ??
                "Nexus could not save the task outcome. Resume the saved run to retry."
        }
    }

    private func finishNotice(_ reason: String?) -> String? {
        switch reason {
        case "length": "The model reached its response limit. You can ask it to continue."
        case "content_filter": "The model reported that a content filter stopped this response."
        case "tool_calls", "function_call": "The model ended this response to request a tool."
        default: nil
        }
    }

    private func clearConversation() {
        do {
            try ai.removeOrchestratedConversation(for: conversationKey)
            transcript = PS5NexusOrchestratedConversation()
            history = []
            output = nil
            showUnattachedResponse = false
            runProgress = nil
            prompt = ""
            UserDefaults.standard.removeObject(forKey: runPreferenceKey)
            activeRunID = nil
        } catch {
            self.error = (error as? LocalizedError)?.errorDescription ??
                "Nexus could not clear this conversation."
        }
    }

    private func resetModelContext() {
        do {
            var updated = transcript
            updated.contextHistory = []
            updated.credentialIdentity = nil
            updated.scopeFingerprint = nil
            updated.updatedAt = .now
            try ai.saveOrchestratedConversation(updated, for: conversationKey)
            transcript = updated
            history = []
            error = nil
        } catch {
            self.error = (error as? LocalizedError)?.errorDescription ??
                "Nexus could not save the reset model context."
        }
    }

    private func discardSavedRun() {
        guard !working, activeRunID != nil || transcript.pendingPrompt != nil ||
              transcript.pendingSubmission != nil else { return }
        do {
            var updated = transcript
            if let prompt = updated.pendingPrompt, !prompt.isEmpty,
               updated.pendingSubmission?.compactOnly != true {
                updated.turns.append(PS5NexusOrchestratedTurn(prompt: prompt, status: "unavailable"))
            }
            updated.contextHistory = []
            updated.credentialIdentity = nil
            updated.scopeFingerprint = nil
            updated.pendingPrompt = nil
            updated.pendingSubmission = nil
            updated.updatedAt = .now
            try ai.saveOrchestratedConversation(updated, for: conversationKey)
            transcript = updated
            history = []
            runProgress = nil
            recoveryBlocked = false
            clearSavedRun()
            error = nil
            taskProgress = "Local run tracking discarded; remote task state was not changed."
        } catch {
            self.error = (error as? LocalizedError)?.errorDescription ??
                "Nexus could not save the local discard. The existing task was preserved."
        }
    }
}

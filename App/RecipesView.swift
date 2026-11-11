import SwiftUI
import NexusCore
import NexusSSH

struct RecipesView: View {
    @Bindable var store: AppStore
    @State private var selectedDeviceID: UUID?
    @State private var selectedEndpointID: UUID?
    @State private var selectedRecipeID: UUID?
    @State private var parameters: [String: String] = [:]
    @State private var useSudo = false
    @State private var showingEditor = false
    @State private var editingRecipe: CommandRecipe?
    @State private var pendingRun = false
    @State private var isRunning = false
    @State private var output: String?
    @State private var outputTarget: String?
    @State private var outputExitCode: Int?
    @State private var outputWasTruncated = false
    @State private var outputTimedOut = false
    @State private var error: String?
    @State private var pendingTrust: PendingHostMetricsTrust?
    @State private var deletingRecipe: CommandRecipe?
    @State private var viewGeneration = UUID()

    private var selectedDevice: Device? { store.devices.first { $0.id == selectedDeviceID } }
    private var selectedEndpoint: Endpoint? { selectedDevice?.endpoints.first { $0.id == selectedEndpointID } }
    private var selectedRecipe: CommandRecipe? { store.commandRecipes.first { $0.id == selectedRecipeID } }
    private var renderedCommand: String? { try? selectedRecipe?.render(parameters: parameters) }
    private var commandPreview: String? {
        guard let renderedCommand else { return nil }
        return useSudo ? "sudo -n sh -c \(Shell.quote(renderedCommand))" : "sh -c \(Shell.quote(renderedCommand))"
    }

    var body: some View {
        Group {
            if store.devices.isEmpty {
                ContentUnavailableView("No devices yet", systemImage: "terminal",
                    description: Text("Add an SSH device before creating command recipes."))
            } else {
                NexusList {
                    Section("Saved recipes") {
                        if store.commandRecipes.isEmpty {
                            ContentUnavailableView("No recipes yet", systemImage: "text.book.closed",
                                description: Text("Save a command template to run it later against a selected device."))
                        } else {
                            ForEach(store.commandRecipes) { recipe in
                                Button {
                                    select(recipe)
                                } label: {
                                    VStack(alignment: .leading, spacing: 4) {
                                        HStack {
                                            Text(recipe.name).font(.headline)
                                            Spacer()
                                            if selectedRecipeID == recipe.id {
                                                Image(systemName: "checkmark.circle.fill").foregroundStyle(.tint)
                                            }
                                        }
                                        Text(recipe.commandTemplate)
                                            .font(.caption.monospaced()).foregroundStyle(.secondary)
                                            .lineLimit(2).textSelection(.enabled)
                                    }
                                    .contentShape(Rectangle())
                                }
                                .buttonStyle(.plain)
                                .disabled(isRunning)
                                .contextMenu {
                                    Button("Edit recipe", systemImage: "pencil") {
                                        editingRecipe = recipe; showingEditor = true
                                    }.disabled(isRunning)
                                    Button("Delete recipe", systemImage: "trash", role: .destructive) {
                                        deletingRecipe = recipe
                                    }.disabled(isRunning)
                                }
                            }
                        }
                        Button("New recipe", systemImage: "plus") {
                            editingRecipe = CommandRecipe(name: "", commandTemplate: "")
                            showingEditor = true
                        }
                        .disabled(isRunning)
                    }

                    if let recipe = selectedRecipe {
                        Section("Run · \(recipe.name)") {
                            Picker("Device", selection: $selectedDeviceID) {
                                Text("Choose device").tag(Optional<UUID>.none)
                                ForEach(store.devices) { device in Text(device.name).tag(Optional(device.id)) }
                            }
                            .disabled(isRunning)
                            if let device = selectedDevice {
                                Picker("Endpoint", selection: $selectedEndpointID) {
                                    ForEach(device.orderedEndpoints) { endpoint in
                                        Text("\(endpoint.authority) · \(endpoint.kind.rawValue.capitalized)")
                                            .tag(Optional(endpoint.id))
                                    }
                                }
                                .disabled(isRunning)
                            }
                            ForEach(recipe.parameterNames, id: \.self) { name in
                                TextField(name, text: parameterBinding(name))
                                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                                    .accessibilityHint("This value is supplied only for this run and is not saved in the recipe or run history.")
                                    .disabled(isRunning)
                            }
                            Toggle("Run with non-interactive sudo", isOn: $useSudo)
                                .disabled(isRunning)
                            Text("Do not enter passwords, tokens, or private keys as parameters. Sudo uses existing server policy and cannot prompt; other parameter values are shell-quoted and not saved.")
                                .font(.footnote).foregroundStyle(.secondary)
                            Group {
                                if let commandPreview {
                                    Text(commandPreview).textSelection(.enabled)
                                } else {
                                    Text("Fill in the recipe parameters to preview the command.")
                                        .foregroundStyle(.secondary)
                                }
                            }
                            .font(.system(.caption, design: .monospaced))
                            .frame(maxWidth: .infinity, alignment: .leading)
                            Button("Review and run", systemImage: "play.fill") {
                                pendingRun = true
                            }
                            .disabled(isRunning || selectedDevice == nil || selectedEndpoint == nil || commandPreview == nil)
                            if isRunning { ProgressView("Running command…") }
                            if let output {
                                if let outputTarget {
                                    Text("Result from \(outputTarget)")
                                        .font(.caption).foregroundStyle(.secondary)
                                }
                                if let outputExitCode {
                                    NexusStatusBadge(
                                        title: outputTimedOut
                                            ? "Timed out · exit \(outputExitCode)"
                                            : "Exit status \(outputExitCode)",
                                        systemImage: outputExitCode == 0 ? "checkmark.circle.fill" : "exclamationmark.circle.fill",
                                        tone: outputExitCode == 0 ? .positive : .caution)
                                }
                                if outputWasTruncated {
                                    Label("Output capped at 64 KiB", systemImage: "text.alignleft")
                                        .font(.caption).foregroundStyle(.secondary)
                                }
                                ScrollView(.vertical) {
                                    Text(output.isEmpty ? "The command returned no output." : output)
                                        .font(.system(.caption, design: .monospaced))
                                        .textSelection(.enabled)
                                        .fixedSize(horizontal: false, vertical: true)
                                        .frame(maxWidth: .infinity, alignment: .leading)
                                        .padding(.vertical, 2)
                                }
                                .frame(maxHeight: 360)
                                .accessibilityIdentifier("recipes.output")
                            }
                        }
                    }

                    Section("Recent activity") {
                        if store.commandHistory.isEmpty {
                            Text("No recipe runs recorded.").foregroundStyle(.secondary)
                        } else {
                            ForEach(store.commandHistory.prefix(20)) { record in
                                HStack {
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(record.recipeName)
                                        Text("\(record.deviceName) · \(record.endpointAuthority)\(record.usedSudo ? " · sudo" : "") · \(record.startedAt.formatted(date: .abbreviated, time: .shortened))")
                                            .font(.caption).foregroundStyle(.secondary)
                                    }
                                    Spacer()
                                    recipeHistoryBadge(for: record)
                                }
                                .accessibilityElement(children: .combine)
                            }
                            Text("History stores recipe/device names, time, and exit status or an unknown-outcome marker. Commands, parameters, and output are not retained.")
                                .font(.footnote).foregroundStyle(.secondary)
                        }
                    }
                }
                .toolbar {
                    ToolbarItem(placement: .principal) {
                        Picker("Device", selection: $selectedDeviceID) {
                            Text("Choose device").tag(Optional<UUID>.none)
                            ForEach(store.devices) { device in Text(device.name).tag(Optional(device.id)) }
                        }
                        .pickerStyle(.menu)
                        .disabled(isRunning)
                    }
                }
                .onChange(of: selectedDeviceID) { _, newID in
                    selectedEndpointID = store.devices.first { $0.id == newID }?.orderedEndpoints.first?.id
                }
                .onChange(of: store.devices) { oldDevices, devices in
                    guard let selectedID = selectedDeviceID,
                          let previousDevice = oldDevices.first(where: { $0.id == selectedID }) else { return }
                    guard let updatedDevice = devices.first(where: { $0.id == selectedID }) else {
                        selectedDeviceID = nil
                        selectedEndpointID = nil
                        parameters = [:]
                        output = nil
                        outputTarget = nil
                        outputExitCode = nil
                        outputWasTruncated = false
                        outputTimedOut = false
                        error = nil
                        pendingRun = false
                        pendingTrust = nil
                        return
                    }
                    guard previousDevice != updatedDevice else { return }
                    let oldEndpoints = Dictionary(uniqueKeysWithValues:
                        previousDevice.endpoints.map { ($0.id, $0.authority) })
                    let newEndpoints = Dictionary(uniqueKeysWithValues:
                        updatedDevice.endpoints.map { ($0.id, $0.authority) })
                    let targetChanged = previousDevice.name != updatedDevice.name
                        || previousDevice.username != updatedDevice.username
                        || previousDevice.authentication != updatedDevice.authentication
                        || oldEndpoints != newEndpoints
                    guard targetChanged else { return }
                    if !updatedDevice.endpoints.contains(where: { $0.id == selectedEndpointID }) {
                        selectedEndpointID = updatedDevice.orderedEndpoints.first?.id
                    }
                    if pendingRun {
                        pendingRun = false
                        error = "The selected device or connection changed. Review the updated target and confirm the command again."
                    }
                    pendingTrust = nil
                    // An already submitted remote command is not canceled here.
                    // Its captured target remains in command history when it finishes.
                }
                .confirmationDialog("Run this command?", isPresented: $pendingRun, titleVisibility: .visible) {
                    Button("Run command", role: .destructive) { executeRecipe() }
                    Button("Cancel", role: .cancel) {}
                } message: {
                    Text("Target: \(selectedDevice?.name ?? "none") · \(selectedEndpoint?.authority ?? "no endpoint")\n\(commandPreview ?? "Invalid command preview")\nThis command may change or delete remote data. Inspect it before running.")
                }
                .alert(pendingTrust?.challenge.changed == true ? "Host key changed" :
                    (pendingTrust == nil ? "Command recipe" : "Verify SSH host"), isPresented: Binding(
                        get: { pendingTrust != nil || error != nil },
                        set: { if !$0 { if pendingTrust != nil { rejectHostTrust() } else { error = nil } }
                    })) {
                    if let challenge = pendingTrust?.challenge {
                        if challenge.changed { Button("OK", role: .cancel) { rejectHostTrust() } }
                        else {
                            Button("Trust host and return") { approveHost() }
                            Button("Cancel", role: .cancel) { rejectHostTrust() }
                        }
                    } else { Button("OK") { error = nil } }
                } message: {
                    if let pendingTrust {
                        Text("\(pendingTrust.device.name) · \(pendingTrust.challenge.endpoint.authority)\n\(pendingTrust.challenge.fingerprint)\nCompare this SHA256 fingerprint through a trusted channel before approving. The command was not run; review and confirm it again after trust.")
                    } else { Text(error ?? "") }
                }
                .sheet(isPresented: $showingEditor) {
                    if let editingRecipe {
                        NavigationStack {
                            RecipeEditorView(recipe: editingRecipe) { updated in
                                do {
                                    try store.saveCommandRecipe(updated)
                                    select(updated)
                                    showingEditor = false
                                } catch { self.error = error.localizedDescription }
                            } onCancel: { showingEditor = false }
                        }
                    }
                }
                .confirmationDialog(
                    deletingRecipe.map { "Delete recipe “\($0.name)”?" } ?? "Delete recipe?",
                    isPresented: Binding(get: { deletingRecipe != nil }, set: { if !$0 { deletingRecipe = nil } })
                ) {
                    Button("Delete", role: .destructive) {
                        if let deletingRecipe { delete(deletingRecipe) }
                        deletingRecipe = nil
                    }
                    Button("Cancel", role: .cancel) { deletingRecipe = nil }
                } message: {
                    Text("The saved template is removed from this iPhone. Recent activity history is kept, but this recipe can no longer be run.")
                }
            }
        }
        .navigationTitle("Recipes")
        .scrollContentBackground(.hidden)
        .nexusScreenBackground()
        .tint(NexusPalette.blue)
    }

    @ViewBuilder
    private func recipeHistoryBadge(for record: CommandRunRecord) -> some View {
        if let exitCode = record.exitCode {
            if exitCode == 0 {
                NexusStatusBadge(title: "Exit 0", systemImage: "checkmark.circle.fill", tone: .positive)
            } else {
                NexusStatusBadge(title: "Exit \(exitCode)", systemImage: "exclamationmark.circle.fill", tone: .caution)
            }
        } else {
            NexusStatusBadge(title: "Outcome unknown", systemImage: "questionmark.circle.fill", tone: .neutral)
        }
    }

    private func select(_ recipe: CommandRecipe) {
        selectedRecipeID = recipe.id
        parameters = Dictionary(uniqueKeysWithValues: recipe.parameterNames.map { ($0, "") })
        output = nil
        outputTarget = nil
        outputExitCode = nil
        outputWasTruncated = false
        outputTimedOut = false
    }

    private func parameterBinding(_ name: String) -> Binding<String> {
        Binding(get: { parameters[name] ?? "" }, set: { parameters[name] = $0 })
    }

    private func delete(_ recipe: CommandRecipe) {
        do {
            try store.removeCommandRecipe(recipe)
            if selectedRecipeID == recipe.id { selectedRecipeID = nil; output = nil }
        } catch let caughtError { self.error = caughtError.localizedDescription }
    }

    @MainActor private func executeRecipe() {
        guard !isRunning, let recipe = selectedRecipe, let device = selectedDevice,
              let endpoint = selectedEndpoint, let command = try? recipe.render(parameters: parameters) else { return }
        let generation = viewGeneration
        let startedAt = Date.now
        isRunning = true; error = nil; output = nil; outputTarget = nil
        outputExitCode = nil; outputWasTruncated = false; outputTimedOut = false
        Task {
            defer { if viewGeneration == generation { isRunning = false } }
            do {
                let result = try await store.commandTransport.run(command, useSudo: useSudo,
                    device: device, endpoint: endpoint, secrets: store.secrets, timeout: store.timeout)
                guard viewGeneration == generation else { return }
                if selectedDeviceID == device.id {
                    output = result.output
                    outputTarget = "\(device.name) · \(device.username)@\(endpoint.authority)"
                    outputExitCode = result.exitCode
                    outputWasTruncated = result.outputTruncated
                    outputTimedOut = result.timedOut
                }
                try store.recordCommandRun(CommandRunRecord(recipeName: recipe.name,
                    deviceName: device.name, endpointAuthority: endpoint.authority,
                    usedSudo: useSudo, startedAt: startedAt, exitCode: result.exitCode))
            } catch let challenge as HostKeyChallenge {
                guard viewGeneration == generation else { return }
                if selectedDeviceID == device.id {
                    pendingTrust = PendingHostMetricsTrust(device: device, challenge: challenge)
                }
            } catch is CancellationError {
                guard viewGeneration == generation else { return }
                do {
                    try store.recordCommandRun(CommandRunRecord(recipeName: recipe.name,
                        deviceName: device.name, endpointAuthority: endpoint.authority,
                        usedSudo: useSudo, startedAt: startedAt, exitCode: nil))
                } catch {
                    if selectedDeviceID == device.id {
                        self.error = "The connection closed and Nexus could not save the run outcome: \(error.localizedDescription)"
                    }
                }
                if selectedDeviceID == device.id, self.error == nil {
                    self.error = "The SSH connection closed before Nexus received a result. The command may have started; check the selected host before retrying."
                }
            } catch {
                guard viewGeneration == generation else { return }
                let exitCode: Int?
                if case CommandTransportError.commandFailed(let code) = error { exitCode = code }
                else { exitCode = nil }
                do {
                    try store.recordCommandRun(CommandRunRecord(recipeName: recipe.name,
                        deviceName: device.name, endpointAuthority: endpoint.authority,
                        usedSudo: useSudo, startedAt: startedAt, exitCode: exitCode))
                } catch {
                    if selectedDeviceID == device.id {
                        self.error = "Run outcome: \(error.localizedDescription)"
                    }
                }
                if selectedDeviceID == device.id, self.error == nil {
                    self.error = error.localizedDescription
                }
            }
        }
    }

    @MainActor private func approveHost() {
        guard let pendingTrust, !pendingTrust.challenge.changed else { return }
        do {
            try HostKeyVerifier.approve(pendingTrust.challenge, secrets: store.secrets)
            self.pendingTrust = nil
            error = nil
        } catch let caughtError { self.error = caughtError.localizedDescription }
    }

    @MainActor private func rejectHostTrust() {
        if pendingTrust != nil { error = "Host key was not approved. No command was run." }
        pendingTrust = nil
    }

}

private struct RecipeEditorView: View {
    @Environment(\.dismiss) private var dismiss
    @State private var name: String
    @State private var command: String
    @State private var error: String?
    let onSave: (CommandRecipe) -> Void
    let onCancel: () -> Void

    init(recipe: CommandRecipe, onSave: @escaping (CommandRecipe) -> Void,
         onCancel: @escaping () -> Void) {
        _name = State(initialValue: recipe.name)
        _command = State(initialValue: recipe.commandTemplate)
        self.onSave = onSave
        self.onCancel = onCancel
    }

    var body: some View {
        NexusForm {
            Section("Recipe") {
                TextField("Name", text: $name)
                Text("Command values use {{parameterName}} placeholders. Values are entered only for each run and shell-quoted; they are not stored.")
                    .font(.footnote).foregroundStyle(.secondary)
                TextEditor(text: $command)
                    .font(.system(.body, design: .monospaced))
                    .frame(minHeight: 180)
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
            }
            Section {
                Text("Every run shows the target and expanded command and requires confirmation. Avoid putting passwords, tokens, or private keys in a recipe. Run history never stores command text, parameter values, or output.")
                    .font(.footnote).foregroundStyle(.secondary)
            }
        }
        .navigationTitle("Command recipe")
        .scrollContentBackground(.hidden)
        .nexusScreenBackground()
        .tint(NexusPalette.blue)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) { Button("Cancel", action: onCancel) }
            ToolbarItem(placement: .confirmationAction) {
                Button("Save") {
                    let recipe = CommandRecipe(name: name, commandTemplate: command)
                    do { try recipe.validate(); onSave(recipe) }
                    catch { self.error = error.localizedDescription }
                }
            }
        }
        .alert("Cannot save recipe", isPresented: Binding(
            get: { error != nil }, set: { if !$0 { error = nil } }
        )) {
            Button("OK", role: .cancel) { error = nil }
        } message: { Text(error ?? "") }
    }
}

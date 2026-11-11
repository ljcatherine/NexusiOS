import SwiftUI
import NexusCore
import NexusSSH

struct ServicesView: View {
    @Bindable var store: AppStore
    @State private var selectedDeviceID: UUID?
    @State private var sourceEndpoint: Endpoint?
    @State private var services: [LinuxService] = []
    @State private var processes: [LinuxProcess] = []
    @State private var systemInspection: LinuxSystemInspection?
    @State private var selectedService: LinuxService?
    @State private var isLoading = false
    @State private var error: String?
    @State private var logs: String?
    @State private var loadingLogs = false
    @State private var loadingProcesses = false
    @State private var loadingInspection = false
    @State private var pendingAction: ServiceAction?
    @State private var pendingNixOSAction: NixOSRebuildAction?
    @State private var nixosFlakeAttribute = ""
    @State private var validatedNixOSTarget: String?
    @State private var nixosOutput: String?
    @State private var isRebuildingNixOS = false
    @State private var pendingTrust: PendingHostMetricsTrust?
    @State private var viewGeneration = UUID()

    private var selectedDevice: Device? { store.devices.first { $0.id == selectedDeviceID } }
    private var transport: ServiceTransport { store.serviceTransport }
    private var hasNixOSFlake: Bool { systemInspection?.configurationFiles.contains("flake.nix") == true }
    private var hasNixOSConfiguration: Bool {
        systemInspection?.configurationFiles.contains("configuration.nix") == true
    }
    private var selectedNixOSTarget: String? {
        guard let device = selectedDevice, let endpoint = sourceEndpoint,
              let systemInspection, systemInspection.isNixOS else { return nil }
        let target: String
        if hasNixOSFlake {
            let attribute = nixosFlakeAttribute.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !attribute.isEmpty,
                  (try? ServiceTransport.nixosCommand(.validate, flakeAttribute: attribute)) != nil else {
                return nil
            }
            target = "flake:\(attribute)"
        } else {
            guard hasNixOSConfiguration else { return nil }
            target = "configuration.nix"
        }
        return "\(device.id.uuidString)|\(endpoint.authority)|\(target)"
    }

    var body: some View {
        Group {
            if store.devices.isEmpty {
                ContentUnavailableView("No devices yet", systemImage: "server.rack",
                    description: Text("Add an SSH device to inspect its system services."))
            } else {
                NexusList {
                    Section {
                        HStack {
                            if let sourceEndpoint {
                                Label(sourceEndpoint.authority, systemImage: "lock.shield")
                                    .font(.caption).foregroundStyle(.secondary)
                            } else {
                                Text("Select a device to inspect services.")
                                    .font(.caption).foregroundStyle(.secondary)
                            }
                            Spacer()
                            if isLoading { ProgressView().controlSize(.small) }
                            Button("Refresh", systemImage: "arrow.clockwise") { loadServices() }
                                .labelStyle(.iconOnly)
                                .frame(minWidth: 44, minHeight: 44)
                                .disabled(isLoading || loadingLogs || loadingProcesses || loadingInspection || isRebuildingNixOS || selectedDevice == nil)
                                .accessibilityLabel("Refresh system services")
                        }
                    }

                    Section("System configuration") {
                        Button("Inspect host system", systemImage: "info.circle") { inspectSystem() }
                        .disabled(selectedDevice == nil || isLoading || loadingLogs || loadingProcesses || loadingInspection || isRebuildingNixOS)
                        if loadingInspection { ProgressView("Inspecting host…") }
                        if let systemInspection {
                            LabeledContent("Distribution", value: systemInspection.distribution)
                            LabeledContent("Kernel", value: systemInspection.kernel)
                            if systemInspection.isNixOS {
                                if let version = systemInspection.nixosVersion {
                                    LabeledContent("NixOS version", value: version)
                                }
                                if let path = systemInspection.activeSystemPath {
                                    LabeledContent("Active generation", value: path)
                                        .font(.caption.monospaced()).textSelection(.enabled)
                                }
                                if systemInspection.configurationFiles.isEmpty {
                                    Text("No conventional configuration file was detected in /etc/nixos.")
                                        .font(.footnote).foregroundStyle(.secondary)
                                } else {
                                    LabeledContent("Detected configuration files",
                                        value: systemInspection.configurationFiles.joined(separator: ", "))
                                }
                            } else {
                                Text("NixOS configuration inspection is unavailable on this host.")
                                    .font(.footnote).foregroundStyle(.secondary)
                            }
                            Text("Nexus does not read configuration contents. NixOS rebuilds require a validated target and a separate confirmation.")
                                .font(.footnote).foregroundStyle(.secondary)
                        }
                    }

                    if let systemInspection, systemInspection.isNixOS,
                       hasNixOSFlake || hasNixOSConfiguration {
                        Section("NixOS configuration") {
                            if hasNixOSFlake {
                                TextField("Flake output attribute", text: $nixosFlakeAttribute)
                                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                                    .accessibilityHint("For example, the host name in nixosConfigurations.")
                                    .disabled(isRebuildingNixOS)
                                Text("Uses /etc/nixos#attribute. Enter the output name from nixosConfigurations.")
                                    .font(.footnote).foregroundStyle(.secondary)
                            } else {
                                Text("Uses /etc/nixos/configuration.nix on this host.")
                                    .font(.footnote).foregroundStyle(.secondary)
                            }

                            Button("Validate configuration", systemImage: "checkmark.shield") {
                                pendingNixOSAction = .validate
                            }
                            .disabled(selectedNixOSTarget == nil || isRebuildingNixOS || isLoading || loadingLogs || loadingProcesses || loadingInspection)

                            if validatedNixOSTarget == selectedNixOSTarget, selectedNixOSTarget != nil {
                                NexusStatusBadge(title: "Dry build succeeded", systemImage: "checkmark.circle.fill", tone: .positive)
                                Button("Rebuild and switch…", systemImage: "arrow.triangle.2.circlepath") {
                                    pendingNixOSAction = .switchSystem
                                }
                                .disabled(isRebuildingNixOS || isLoading || loadingLogs || loadingProcesses || loadingInspection)
                            }

                            if isRebuildingNixOS { ProgressView("Running NixOS operation…") }
                            if let nixosOutput {
                                ScrollView(.vertical) {
                                    Text(nixosOutput.isEmpty ? "Command completed successfully." : nixosOutput)
                                        .font(.system(.caption, design: .monospaced))
                                        .textSelection(.enabled)
                                        .frame(maxWidth: .infinity, alignment: .leading)
                                }
                                .frame(maxHeight: 220)
                            }
                            Text("A dry build can use significant CPU, network, and disk and may take up to 30 minutes. Switching changes the running operating system and may interrupt SSH. Commands use sudo -n and the server's existing policy. If the connection drops during a switch, inspect the active generation before retrying.")
                                .font(.footnote).foregroundStyle(.secondary)
                        }
                    }

                    Section("Systemd services") {
                        if selectedDevice == nil {
                            ContentUnavailableView("Choose a device", systemImage: "externaldrive",
                                description: Text("Select an SSH device above to load its services."))
                        } else if isLoading && services.isEmpty {
                            HStack { ProgressView(); Text("Loading system services…").foregroundStyle(.secondary) }
                        } else if let error, services.isEmpty {
                            ContentUnavailableView {
                                Label("Services unavailable", systemImage: "network.slash")
                            } description: {
                                Text(error)
                            } actions: {
                                Button("Retry") { loadServices() }
                                    .buttonStyle(.borderedProminent)
                                    .disabled(isLoading || loadingLogs || loadingProcesses || loadingInspection || isRebuildingNixOS)
                            }
                        } else if services.isEmpty {
                            ContentUnavailableView("No services found", systemImage: "gearshape.2",
                                description: Text("The host returned no systemd services."))
                        } else {
                            ForEach(services) { service in serviceRow(service) }
                        }
                    }

                    Section("Top processes · CPU") {
                        Button("Load process snapshot", systemImage: "cpu") { loadProcesses() }
                            .disabled(selectedDevice == nil || isLoading || loadingLogs || loadingProcesses || loadingInspection || isRebuildingNixOS)
                        if loadingProcesses { ProgressView("Reading process list…") }
                        ForEach(processes) { process in
                            HStack(alignment: .firstTextBaseline, spacing: 8) {
                                Text(process.command).font(.body.monospaced()).lineLimit(1)
                                Spacer(minLength: 4)
                                Text("\(process.cpuPercent, specifier: "%.1f")% CPU")
                                    .font(.caption.monospacedDigit())
                                Text("\(process.memoryPercent, specifier: "%.1f")% RAM")
                                    .font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                            }
                            .accessibilityElement(children: .combine)
                            .accessibilityLabel("\(process.command), process \(process.pid), user \(process.user), \(process.cpuPercent, specifier: "%.1f") percent CPU, \(process.memoryPercent, specifier: "%.1f") percent memory, state \(process.state)")
                        }
                        if !processes.isEmpty {
                            Text("Top 20 by CPU · command arguments are omitted")
                                .font(.footnote).foregroundStyle(.secondary)
                        }
                    }

                    if let selectedService {
                        Section("\(selectedService.name) · \(selectedService.activeState)/\(selectedService.subState)") {
                            if !selectedService.description.isEmpty {
                                Text(selectedService.description).font(.subheadline)
                            }
                            LabeledContent("Loaded", value: selectedService.loadState)
                            LabeledContent("State", value: "\(selectedService.activeState) · \(selectedService.subState)")
                            Button("Load recent logs", systemImage: "text.alignleft") { loadLogs(for: selectedService) }
                                .disabled(loadingLogs || isLoading || loadingProcesses || loadingInspection || isRebuildingNixOS)
                            if loadingLogs { ProgressView("Reading journal…") }
                            if let logs {
                                Text(logs.isEmpty ? "No recent journal output was returned." : logs)
                                    .font(.system(.caption, design: .monospaced))
                                    .textSelection(.enabled)
                                    .frame(maxHeight: 320, alignment: .topLeading)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                            }
                            Menu("Service actions", systemImage: "ellipsis.circle") {
                                ForEach(ServiceAction.allCases, id: \.self) { action in
                                    Button(action.rawValue.capitalized, systemImage: actionSymbol(action)) {
                                        pendingAction = action
                                    }
                                }
                            }
                            .disabled(isLoading || loadingLogs || loadingProcesses || loadingInspection || isRebuildingNixOS)
                            Text("Choose whether each confirmed action runs as the SSH user or uses non-interactive sudo. Sudo works only if the server already permits it; Nexus does not change server permissions.")
                                .font(.footnote).foregroundStyle(.secondary)
                        }
}
                    if let error, !services.isEmpty {
                        Section { Label(error, systemImage: "exclamationmark.triangle.fill")
                            .font(.footnote).foregroundStyle(.orange) }
                    }
                }
                .toolbar {
                    ToolbarItem(placement: .principal) {
                        Picker("Device", selection: $selectedDeviceID) {
                            Text("Choose device").tag(Optional<UUID>.none)
                            ForEach(store.devices) { device in Text(device.name).tag(Optional(device.id)) }
                        }
                        .pickerStyle(.menu)
                        .disabled(isLoading || loadingLogs || loadingProcesses || loadingInspection || isRebuildingNixOS)
                    }
                }
                .confirmationDialog(confirmationTitle, isPresented: Binding(
                    get: { pendingAction != nil || pendingNixOSAction != nil },
                    set: { if !$0 { pendingAction = nil; pendingNixOSAction = nil } }),
                    titleVisibility: .visible) {
                    if let pendingNixOSAction {
                        Button(pendingNixOSAction == .validate ? "Run dry build" : "Rebuild and switch", role: pendingNixOSAction == .validate ? nil : .destructive) {
                            runNixOS(pendingNixOSAction)
                        }
                    } else if let pendingAction {
                        Button("Run as SSH user", role: .destructive) { perform(pendingAction, useSudo: false) }
                        Button("Run with sudo", role: .destructive) { perform(pendingAction, useSudo: true) }
                    }
                    Button("Cancel", role: .cancel) { pendingAction = nil; pendingNixOSAction = nil }
                } message: {
                    if pendingNixOSAction != nil {
                        Text(nixosConfirmationMessage)
                    } else if let selectedService, let pendingAction {
                        Text(serviceConfirmationMessage(for: pendingAction, service: selectedService))
                    }
                }
                .alert(pendingTrust?.challenge.changed == true ? "Host key changed" :
                    (pendingTrust == nil ? "Services" : "Verify SSH host"), isPresented: Binding(
                        get: { pendingTrust != nil || (error != nil && !isLoading && !loadingLogs && !loadingProcesses && !loadingInspection && !isRebuildingNixOS) },
                        set: { if !$0 { if pendingTrust != nil { rejectHostTrust() } else { error = nil } }
                    })) {
                    if let challenge = pendingTrust?.challenge {
                        if challenge.changed { Button("OK", role: .cancel) { rejectHostTrust() } }
                        else {
                            Button("Trust and refresh") { approveHost() }
                            Button("Cancel", role: .cancel) { rejectHostTrust() }
                        }
                    } else { Button("OK") { error = nil } }
                } message: {
                    if let pendingTrust {
                        let challenge = pendingTrust.challenge
                        Text("\(pendingTrust.device.name) · \(challenge.endpoint.authority)\n\(challenge.fingerprint)\n\(challenge.changed ? "Connection blocked. Verify the new key through a trusted channel and recover it in the terminal." : "Compare this SHA256 fingerprint through a trusted channel before approving it.")")
                    } else { Text(error ?? "") }
                }
                .onChange(of: selectedDeviceID) { _, _ in
                    viewGeneration = UUID()
                    services = []; selectedService = nil; sourceEndpoint = nil; logs = nil; error = nil
                    processes = []; systemInspection = nil
                    nixosFlakeAttribute = ""; validatedNixOSTarget = nil; nixosOutput = nil
                    isRebuildingNixOS = false; pendingNixOSAction = nil
                    isLoading = false; loadingLogs = false; loadingProcesses = false; loadingInspection = false
                    if selectedDeviceID != nil { loadServices() }
                }
                .onChange(of: store.devices) { oldDevices, devices in
                    guard let selectedDeviceID else { return }
                    let previousDevice = oldDevices.first(where: { $0.id == selectedDeviceID })
                    guard let updatedDevice = devices.first(where: { $0.id == selectedDeviceID }) else {
                        self.selectedDeviceID = nil
                        return
                    }
                    guard previousDevice != updatedDevice else { return }
                    if let sourceEndpoint,
                       let retainedEndpoint = updatedDevice.endpoints.first(where: {
                           $0.authority == sourceEndpoint.authority
                       }) {
                        self.sourceEndpoint = retainedEndpoint
                        return
                    }

                    viewGeneration = UUID()
                    services = []; selectedService = nil; sourceEndpoint = nil
                    logs = nil; processes = []; systemInspection = nil
                    validatedNixOSTarget = nil; nixosOutput = nil
                    pendingAction = nil; pendingNixOSAction = nil; pendingTrust = nil
                    isLoading = false; loadingLogs = false; loadingProcesses = false; loadingInspection = false
                    loadServices()
                }
                .onChange(of: nixosFlakeAttribute) { _, _ in validatedNixOSTarget = nil }
            }
        }
        .navigationTitle("Services")
        .scrollContentBackground(.hidden)
        .nexusScreenBackground()
        .tint(NexusPalette.blue)
    }

    @ViewBuilder
    private func serviceRow(_ service: LinuxService) -> some View {
        Button {
            selectedService = service
            logs = nil
        } label: {
            HStack(spacing: 12) {
                VStack(alignment: .leading, spacing: 3) {
                    Text(service.name).font(.body.monospaced())
                    Text(service.description.isEmpty ? service.loadState : service.description)
                        .font(.caption).foregroundStyle(.secondary).lineLimit(2)
                    NexusStatusBadge(title: "\(service.activeState) · \(service.subState)",
                        systemImage: service.isActive ? "checkmark.circle.fill" :
                            (service.activeState == "failed" ? "xmark.circle.fill" : "pause.circle"),
                        tone: service.isActive ? .positive :
                            (service.activeState == "failed" ? .critical : .neutral))
                }
                Spacer()
                Image(systemName: "chevron.right").font(.caption).foregroundStyle(.tertiary)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityIdentifier("services.row.\(service.name)")
    }

    @MainActor private func loadServices() {
        guard let device = selectedDevice, !isLoading else { return }
        let generation = viewGeneration
        isLoading = true; error = nil
        Task {
            defer { if viewGeneration == generation { isLoading = false } }
            var endpoints = device.orderedEndpoints
            if let sourceEndpoint { endpoints = [sourceEndpoint] + endpoints.filter { $0.id != sourceEndpoint.id } }
            var lastError: Error?
            for endpoint in endpoints {
                do {
                    let result = try await transport.listServices(device: device, endpoint: endpoint,
                        secrets: store.secrets, timeout: store.timeout)
                    guard viewGeneration == generation else { return }
                    if sourceEndpoint?.authority != endpoint.authority {
                        systemInspection = nil
                        validatedNixOSTarget = nil
                        nixosOutput = nil
                    }
                    services = result; sourceEndpoint = endpoint
                    store.cacheServiceInventory(result, for: device, endpoint: endpoint)
                    if let selectedService { self.selectedService = result.first { $0.name == selectedService.name } }
                    return
                } catch let challenge as HostKeyChallenge {
                    guard viewGeneration == generation else { return }
                    pendingTrust = PendingHostMetricsTrust(device: device, challenge: challenge)
                    return
                } catch {
                    guard viewGeneration == generation else { return }
                    lastError = error
                    if let failure = error as? SSHFailure, case .connectionFailed = failure { continue }
                    self.error = error.localizedDescription
                    return
                }
            }
            guard viewGeneration == generation else { return }
            error = lastError?.localizedDescription ?? SSHFailure.connectionFailed.localizedDescription
        }
    }

    @MainActor private func loadLogs(for service: LinuxService) {
        guard let device = selectedDevice, let endpoint = sourceEndpoint, !loadingLogs else { return }
        let generation = viewGeneration
        loadingLogs = true; error = nil
        Task {
            defer { if viewGeneration == generation { loadingLogs = false } }
            do {
                let result = try await transport.recentLogs(for: service.name, device: device,
                    endpoint: endpoint, secrets: store.secrets, timeout: store.timeout)
                guard viewGeneration == generation else { return }
                logs = result
            } catch let challenge as HostKeyChallenge {
                guard viewGeneration == generation else { return }
                pendingTrust = PendingHostMetricsTrust(device: device, challenge: challenge)
            } catch {
                guard viewGeneration == generation else { return }
                self.error = error.localizedDescription
            }
        }
    }

    @MainActor private func loadProcesses() {
        guard let device = selectedDevice, let endpoint = sourceEndpoint, !loadingProcesses else { return }
        let generation = viewGeneration
        loadingProcesses = true; error = nil
        Task {
            defer { if viewGeneration == generation { loadingProcesses = false } }
            do {
                let result = try await transport.topProcesses(device: device, endpoint: endpoint,
                    secrets: store.secrets, timeout: store.timeout)
                guard viewGeneration == generation else { return }
                processes = result
            } catch let challenge as HostKeyChallenge {
                guard viewGeneration == generation else { return }
                pendingTrust = PendingHostMetricsTrust(device: device, challenge: challenge)
            } catch {
                guard viewGeneration == generation else { return }
                self.error = error.localizedDescription
            }
        }
    }

    @MainActor private func inspectSystem() {
        guard let device = selectedDevice, let endpoint = sourceEndpoint,
              !loadingInspection, !isLoading, !loadingLogs, !loadingProcesses else { return }
        let generation = viewGeneration
        loadingInspection = true; error = nil
        Task {
            defer { if viewGeneration == generation { loadingInspection = false } }
            do {
                let result = try await transport.inspectSystem(device: device, endpoint: endpoint,
                    secrets: store.secrets, timeout: store.timeout)
                guard viewGeneration == generation else { return }
                systemInspection = result
            } catch let challenge as HostKeyChallenge {
                guard viewGeneration == generation else { return }
                pendingTrust = PendingHostMetricsTrust(device: device, challenge: challenge)
            } catch {
                guard viewGeneration == generation else { return }
                self.error = error.localizedDescription
            }
        }
    }

    @MainActor private func perform(_ action: ServiceAction, useSudo: Bool) {
        guard let device = selectedDevice, let endpoint = sourceEndpoint,
              let service = selectedService, !isLoading else { return }
        let generation = viewGeneration
        pendingAction = nil
        isLoading = true; error = nil
        Task {
            var refreshingAfterAction = false
            defer { if !refreshingAfterAction && viewGeneration == generation { isLoading = false } }
            do {
                _ = try await transport.perform(action, on: service.name, useSudo: useSudo, device: device,
                    endpoint: endpoint, secrets: store.secrets, timeout: store.timeout)
                guard viewGeneration == generation else { return }
                try await Task.sleep(for: .seconds(1))
                guard viewGeneration == generation else { return }
                isLoading = false
                refreshingAfterAction = true
                loadServices()
            } catch let challenge as HostKeyChallenge {
                guard viewGeneration == generation else { return }
                pendingTrust = PendingHostMetricsTrust(device: device, challenge: challenge)
            } catch {
                guard viewGeneration == generation else { return }
                self.error = error.localizedDescription
            }
        }
    }

    @MainActor private func approveHost() {
        guard let pendingTrust, !pendingTrust.challenge.changed else { return }
        do {
            try HostKeyVerifier.approve(pendingTrust.challenge, secrets: store.secrets)
            sourceEndpoint = pendingTrust.challenge.endpoint
            self.pendingTrust = nil
            loadServices()
        } catch let caughtError { self.error = caughtError.localizedDescription }
    }

    @MainActor private func rejectHostTrust() {
        if pendingTrust != nil { error = "Host key was not approved. No service request was made." }
        pendingTrust = nil
    }

    private var confirmationTitle: String {
        if let pendingNixOSAction {
            return pendingNixOSAction == .validate ? "Validate NixOS configuration?" : "Rebuild and switch NixOS?"
        }
        guard let pendingAction, let selectedService else { return "Confirm service action" }
        return "\(pendingAction.rawValue.capitalized) \(selectedService.name)?"
    }

    private var nixosConfirmationMessage: String {
        guard let pendingNixOSAction,
              let command = try? ServiceTransport.nixosCommand(pendingNixOSAction,
                flakeAttribute: hasNixOSFlake
                    ? nixosFlakeAttribute.trimmingCharacters(in: .whitespacesAndNewlines)
                    : nil) else {
            return "Choose a valid NixOS target before continuing."
        }
        let target = selectedDevice?.name ?? "NixOS host"
        return "Target: \(target) · \(sourceEndpoint?.authority ?? "")\nExact command: \(command)\nThe command uses sudo -n and does not prompt. It is limited to 30 minutes. \(pendingNixOSAction == .validate ? "Dry build validates/evaluates and builds the selected configuration but does not activate it." : "This repeats the dry build and switches the running system. It may interrupt SSH or other services.")"
    }

    private func serviceConfirmationMessage(for action: ServiceAction, service: LinuxService) -> String {
        let host = selectedDevice?.name ?? "Unknown device"
        let endpoint = sourceEndpoint?.authority ?? "Unknown endpoint"
        return "Host: \(host) · \(endpoint)\nService: \(service.name)\nAs SSH user: systemctl \(action.rawValue) \(service.name)\nWith sudo: sudo -n systemctl \(action.rawValue) \(service.name)\nSudo relies on existing server policy and cannot prompt for a password. \(actionImpact(action))"
    }

    @MainActor private func runNixOS(_ action: NixOSRebuildAction) {
        guard let device = selectedDevice, let endpoint = sourceEndpoint,
              let target = selectedNixOSTarget, !isRebuildingNixOS else { return }
        let attribute = hasNixOSFlake
            ? nixosFlakeAttribute.trimmingCharacters(in: .whitespacesAndNewlines)
            : nil
        guard (try? ServiceTransport.nixosCommand(action, flakeAttribute: attribute)) != nil else {
            error = ServiceTransportError.invalidNixOSFlakeAttribute.localizedDescription
            pendingNixOSAction = nil
            return
        }
        guard action != .switchSystem || validatedNixOSTarget == target else {
            error = "Validate this exact NixOS target before switching."
            pendingNixOSAction = nil
            return
        }
        let generation = viewGeneration
        pendingNixOSAction = nil
        isRebuildingNixOS = true
        error = nil
        nixosOutput = nil
        validatedNixOSTarget = nil
        Task {
            defer { if viewGeneration == generation { isRebuildingNixOS = false } }
            do {
                let result = try await transport.rebuildNixOS(action, flakeAttribute: attribute,
                    device: device, endpoint: endpoint, secrets: store.secrets, timeout: store.timeout)
                guard viewGeneration == generation else { return }
                nixosOutput = result.output
                guard result.succeeded else {
                    validatedNixOSTarget = nil
                    error = ServiceTransportError.commandFailed(exitCode: result.exitCode).localizedDescription
                    return
                }
                if action == .validate {
                    validatedNixOSTarget = target
                } else {
                    validatedNixOSTarget = nil
                    nixosOutput = "Switch command completed; refreshed active generation metadata is shown above.\n\(result.output)"
                    do {
                        let updatedInspection = try await transport.inspectSystem(device: device,
                            endpoint: endpoint, secrets: store.secrets, timeout: store.timeout)
                        guard viewGeneration == generation else { return }
                        systemInspection = updatedInspection
                    } catch {
                        guard viewGeneration == generation else { return }
                        nixosOutput = (nixosOutput ?? "") + "\nCould not refresh active generation metadata: \(error.localizedDescription)"
                    }
                }
            } catch let challenge as HostKeyChallenge {
                guard viewGeneration == generation else { return }
                validatedNixOSTarget = nil
                pendingTrust = PendingHostMetricsTrust(device: device, challenge: challenge)
            } catch {
                guard viewGeneration == generation else { return }
                if action == .switchSystem {
                    validatedNixOSTarget = nil
                    nixosOutput = "The switch did not return a confirmed result. Inspect the active generation before retrying."
                }
                self.error = error.localizedDescription
            }
        }
    }

    private func actionImpact(_ action: ServiceAction) -> String {
        switch action {
        case .start: return "Starting it may launch workloads or accept connections."
        case .stop: return "Stopping it may interrupt active users or workloads."
        case .restart: return "Restarting it interrupts active users or workloads."
        }
    }

    private func actionSymbol(_ action: ServiceAction) -> String {
        switch action {
        case .start: return "play.fill"
        case .stop: return "stop.fill"
        case .restart: return "arrow.clockwise"
        }
    }
}

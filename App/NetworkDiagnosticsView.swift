import SwiftUI
import NexusCore

struct NetworkDiagnosticsView: View {
    @Bindable var store: AppStore
    @State private var selectedDeviceID: UUID?
    @State private var results: [UUID: EndpointProbeResult] = [:]
    @State private var probing = false
    @State private var probeTask: Task<Void, Never>?
    @State private var probeGeneration = UUID()
    @State private var lastProbe: Date?
    @State private var dnsResults: [UUID: EndpointDNSProbeResult] = [:]
    @State private var resolvingDNS = false
    @State private var dnsTask: Task<Void, Never>?
    @State private var dnsGeneration = UUID()
    @State private var lastDNSLookup: Date?
    @State private var discovery = SSHServiceDiscovery()
    @State private var addingDevice: Device?

    private var selectedDevice: Device? { store.devices.first { $0.id == selectedDeviceID } }

    var body: some View {
        NexusList {
            discoverySection
            if store.devices.isEmpty {
                Section {
                    ContentUnavailableView("No saved devices", systemImage: "network.slash",
                        description: Text("Search for an SSH service above, or add a device from the Devices tab."))
                }
            } else {
                    Section {
                        Text("Checks whether each saved host accepts a TCP connection on its configured port. This does not verify SSH credentials, host keys, or server identity.")
                            .font(.footnote).foregroundStyle(.secondary)
                        Button {
                            runProbe()
                        } label: {
                            if probing { Label("Checking endpoints…", systemImage: "hourglass") }
                            else { Label("Check saved endpoints", systemImage: "dot.radiowaves.left.and.right") }
                        }
                        .disabled(selectedDevice == nil || probing || resolvingDNS)
                        if let lastProbe {
                            LabeledContent("Last checked", value: lastProbe.formatted(date: .omitted, time: .shortened))
                        }
                    }
                    dnsSection
                    Section("Saved endpoints") {
                        if let selectedDevice {
                            ForEach(selectedDevice.orderedEndpoints) { endpoint in
                                VStack(alignment: .leading, spacing: 5) {
                                    HStack {
                                        Text(endpoint.authority).font(.body.monospaced())
                                        Spacer()
                                        Text(endpoint.kind.rawValue.capitalized)
                                            .font(.caption).foregroundStyle(.secondary)
                                    }
                                    if let result = results[endpoint.id] {
                                        NexusStatusBadge(title: result.summary,
                                            systemImage: result.isReachable ? "checkmark.circle.fill" : "xmark.circle.fill",
                                            tone: result.isReachable ? .positive : .critical)
                                            .textSelection(.enabled)
                                    } else {
                                        Text("Not checked")
                                            .font(.caption).foregroundStyle(.secondary)
                                    }
                                    if let result = dnsResults[endpoint.id] {
                                        switch result {
                                        case .resolved(let addresses, let milliseconds):
                                            let addressCount = addresses.count
                                            HStack(spacing: 4) {
                                                Image(systemName: "checkmark.circle")
                                                Text("Resolved \(addressCount) address(es) · \(milliseconds) ms")
                                            }
                                            .font(.caption).foregroundStyle(.secondary)
                                            Text(addresses.joined(separator: ", "))
                                                .font(.caption.monospaced()).textSelection(.enabled)
                                        case .failed(let reason):
                                            Label("Resolution failed · \(reason)", systemImage: "xmark.circle")
                                                .font(.caption).foregroundStyle(.secondary)
                                        }
                                    } else {
                                        Text("Name resolution not checked")
                                            .font(.caption).foregroundStyle(.secondary)
                                    }
                                }
                                .accessibilityElement(children: .combine)
                            }
                        } else {
                            ContentUnavailableView("Choose a device", systemImage: "externaldrive",
                                description: Text("Select a saved SSH device above."))
                        }
                    }
            }
        }
        .toolbar {
            if !store.devices.isEmpty {
                ToolbarItem(placement: .principal) {
                    Picker("Device", selection: $selectedDeviceID) {
                        Text("Choose device").tag(Optional<UUID>.none)
                        ForEach(store.devices) { device in Text(device.name).tag(Optional(device.id)) }
                    }
                    .pickerStyle(.menu)
                    .disabled(probing || resolvingDNS)
                }
            }
        }
        .onChange(of: selectedDeviceID) { _, _ in
            probeGeneration = UUID()
            probeTask?.cancel(); probeTask = nil
            probing = false; results = [:]; lastProbe = nil
            dnsTask?.cancel(); dnsTask = nil
            resolvingDNS = false; dnsResults = [:]; lastDNSLookup = nil
            dnsGeneration = UUID()
        }
        .onChange(of: store.devices) { oldDevices, devices in
            guard let selectedID = selectedDeviceID,
                  let previousDevice = oldDevices.first(where: { $0.id == selectedID }) else { return }
            guard let updatedDevice = devices.first(where: { $0.id == selectedID }) else {
                clearProbeResults()
                selectedDeviceID = nil
                return
            }
            let previousAuthorities = Dictionary(uniqueKeysWithValues:
                previousDevice.endpoints.map { ($0.id, $0.authority) })
            let updatedAuthorities = Dictionary(uniqueKeysWithValues:
                updatedDevice.endpoints.map { ($0.id, $0.authority) })
            guard previousAuthorities != updatedAuthorities else { return }
            clearProbeResults()
        }
        .navigationTitle("Network")
        .scrollContentBackground(.hidden)
        .nexusScreenBackground()
        .tint(NexusPalette.blue)
        .onDisappear {
            discovery.stop(); probeGeneration = UUID(); probeTask?.cancel()
            probeTask = nil; probing = false
            dnsTask?.cancel(); dnsTask = nil; resolvingDNS = false
            dnsGeneration = UUID()
        }
        .sheet(item: $addingDevice) { device in
            NavigationStack { DeviceEditor(store: store, device: device) }
        }
    }

    private func clearProbeResults() {
        probeGeneration = UUID()
        probeTask?.cancel(); probeTask = nil
        probing = false; results = [:]; lastProbe = nil
        dnsTask?.cancel(); dnsTask = nil
        resolvingDNS = false; dnsResults = [:]; lastDNSLookup = nil
        dnsGeneration = UUID()
    }

    private var discoverySection: some View {
        Section("Local SSH discovery") {
            Text("Search the local network for devices advertising SSH over Bonjour. Advertisements are unverified candidates; discovery does not connect or trust them.")
                .font(.footnote).foregroundStyle(.secondary)
            Button(discovery.isSearching ? "Stop discovery" : "Search for SSH services",
                systemImage: discovery.isSearching ? "stop.fill" : "dot.radiowaves.left.and.right") {
                if discovery.isSearching { discovery.stop() }
                else { discovery.start() }
            }
            if discovery.isSearching { ProgressView("Searching for up to 15 seconds…") }
            if let error = discovery.error {
                Label(error, systemImage: "exclamationmark.triangle")
                    .font(.footnote).foregroundStyle(.orange)
            }
            if discovery.services.isEmpty && !discovery.isSearching && discovery.error == nil {
                Text("No discovery results yet.").font(.caption).foregroundStyle(.secondary)
            }
            ForEach(discovery.services) { service in
                VStack(alignment: .leading, spacing: 6) {
                    Text(service.name).font(.headline)
                    Text("\(service.host):\(service.port) · Bonjour advertisement · unverified")
                        .font(.caption.monospaced()).foregroundStyle(.secondary)
                        .textSelection(.enabled)
                    Menu("Add as endpoint candidate", systemImage: "plus.circle") {
                        ForEach(store.devices) { device in
                            Button(device.name) { add(service, to: device) }
                        }
                        Button("Create device profile…") { createProfile(for: service) }
                    }
                }
                .accessibilityElement(children: .contain)
            }
        }
    }

    private var dnsSection: some View {
        Section("DNS resolution") {
            Text("Resolve saved endpoint names to addresses. Results describe DNS only; they do not test TCP reachability, authenticate SSH, or verify host identity. The app stops waiting after 8 seconds and discards late results.")
                .font(.footnote).foregroundStyle(.secondary)
            Button {
                runDNSLookup()
            } label: {
                if resolvingDNS { Label("Resolving names…", systemImage: "hourglass") }
                else { Label("Resolve saved endpoint names", systemImage: "magnifyingglass") }
            }
            .disabled(selectedDevice == nil || resolvingDNS || probing)
            if resolvingDNS {
                Button("Stop waiting", role: .cancel) {
                    dnsGeneration = UUID()
                    dnsTask?.cancel(); dnsTask = nil
                    resolvingDNS = false
                }
            }
            if let lastDNSLookup {
                LabeledContent("Last resolved", value: lastDNSLookup.formatted(date: .omitted, time: .shortened))
            }
        }
    }

    @MainActor private func runProbe() {
        guard let device = selectedDevice, !probing else { return }
        let generation = UUID()
        probeGeneration = generation
        probing = true
        results = [:]
        probeTask = Task {
            defer {
                if probeGeneration == generation { probing = false; probeTask = nil }
            }
            for endpoint in device.orderedEndpoints {
                guard !Task.isCancelled, probeGeneration == generation else { return }
                let result = await EndpointProbe.check(endpoint)
                guard !Task.isCancelled, probeGeneration == generation else { return }
                results[endpoint.id] = result
            }
            lastProbe = .now
        }
    }

    @MainActor private func runDNSLookup() {
        guard let device = selectedDevice, !resolvingDNS, !probing else { return }
        let generation = UUID()
        dnsGeneration = generation
        resolvingDNS = true
        dnsResults = [:]
        dnsTask = Task {
            defer {
                if dnsGeneration == generation { resolvingDNS = false; dnsTask = nil }
            }
            for endpoint in device.orderedEndpoints {
                guard !Task.isCancelled, dnsGeneration == generation else { return }
                let result = await EndpointDNSProbe.resolve(endpoint)
                guard !Task.isCancelled, dnsGeneration == generation else { return }
                dnsResults[endpoint.id] = result
            }
            lastDNSLookup = .now
        }
    }

    @MainActor private func add(_ service: DiscoveredSSHService, to device: Device) {
        var updated = device
        let candidate = Endpoint(host: service.host, port: service.port, kind: .lan,
            priority: min(99, (device.endpoints.map(\.priority).max() ?? -1) + 1))
        guard !device.endpoints.contains(where: { $0.authority == candidate.authority }) else {
            discovery.error = "That endpoint is already saved for \(device.name)."
            return
        }
        updated.endpoints.append(candidate)
        Task {
            do { try await store.save(updated, credential: nil) }
            catch { discovery.error = "Could not save the endpoint candidate: \(error.localizedDescription)" }
        }
    }

    @MainActor private func createProfile(for service: DiscoveredSSHService) {
        let endpoint = Endpoint(host: service.host, port: service.port, kind: .lan)
        addingDevice = Device(name: service.name, username: "", endpoints: [endpoint])
    }
}

private extension EndpointProbeResult {
    var isReachable: Bool {
        if case .reachable = self { return true }
        return false
    }
}

import SwiftUI
import Charts
import NexusCore

struct DashboardView: View {
    @Bindable var store: AppStore
    let onOpen: (Device) -> Void
    let onOpenDevices: () -> Void
    let onOpenSessions: () -> Void
    let onOpenAI: () -> Void
    let onOpenServices: () -> Void
    let onOpenSettings: () -> Void
    let aiConnectionCount: Int
    let aiSummary: AIOverviewSummary?
    let isActive: Bool

    @Environment(\.scenePhase) private var scenePhase
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize
    @State private var selectedDeviceID: UUID?
    @State private var automaticRefresh = true
    @State private var contentWidth: CGFloat = 360

    private var metricColumnCount: Int {
        if dynamicTypeSize.isAccessibilitySize || contentWidth < 330 { return 1 }
        return contentWidth >= 780 ? 4 : 2
    }

    private var metricColumns: [GridItem] {
        (0..<metricColumnCount).map { _ in
            GridItem(.flexible(minimum: 0), spacing: NexusLayout.standardSpacing, alignment: .top)
        }
    }

    private var selectedDevice: Device? {
        store.devices.first(where: { $0.id == selectedDeviceID }) ?? store.devices.first
    }

    private var monitorState: HostMonitorState? {
        selectedDevice.flatMap { store.hostMonitorStates[$0.id] }
    }

    private var snapshot: HostMetricsSnapshot? { monitorState?.snapshot }

    private var currentHistory: [HostMetricsHistoryRecord] {
        guard let selectedDevice, let source = monitorState?.sourceEndpoint else { return [] }
        return (store.metricsHistory[selectedDevice.id] ?? []).filter {
            $0.belongs(to: selectedDevice) && $0.endpoint.authority == source.authority
        }
    }

    private var networkRates: (download: Double, upload: Double)? {
        guard let selectedDevice else { return nil }
        let rates = HostNetworkRateCalculator.rates(for: selectedDevice.id, in: currentHistory)
        guard !rates.isEmpty else { return nil }
        return (rates.reduce(0) { $0 + $1.receivedBytesPerSecond },
                rates.reduce(0) { $0 + $1.transmittedBytesPerSecond })
    }

    private var memoryUsedPercent: Double? {
        guard let total = snapshot?.memoryTotalBytes, let available = snapshot?.memoryAvailableBytes,
              total > 0, available <= total else { return nil }
        return Double(total - available) / Double(total) * 100
    }

    private var storageUsedPercent: Double? {
        guard let filesystem = snapshot?.rootFilesystem, filesystem.totalBytes > 0,
              filesystem.usedBytes <= filesystem.totalBytes else { return nil }
        return Double(filesystem.usedBytes) / Double(filesystem.totalBytes) * 100
    }

    private var status: (title: String, icon: String, tone: NexusStatusTone) {
        if store.sessions.contains(where: { $0.device.id == selectedDevice?.id && $0.state == .connected }) {
            return ("SSH connected", "checkmark.circle.fill", .positive)
        }
        if monitorState?.isRefreshing == true { return ("Checking", "arrow.clockwise", .caution) }
        if let error = monitorState?.error, !error.isEmpty {
            return (snapshot == nil ? "Unavailable" : "Last check failed", "exclamationmark.triangle.fill", .critical)
        }
        if snapshot != nil { return ("Sample available", "clock", .neutral) }
        return ("Not checked", "questionmark.circle", .neutral)
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: NexusLayout.sectionSpacing) {
                NexusScreenHeader(title: "Overview", subtitle: overviewSubtitle) {
                    if selectedDevice != nil { refreshButton }
                }
                if store.devices.isEmpty {
                    NexusStateCard(title: "Connect your first device",
                        detail: "Add an SSH profile to view real host resources and open a terminal.",
                        systemImage: "server.rack", actionTitle: "Add a device", action: onOpenDevices)
                } else {
                    aiCard
                    deviceSelector
                    if snapshot == nil && monitorState?.isRefreshing != true {
                        Text("Tap Check to measure this host. A first connection asks you to verify its host key.")
                            .font(NexusTypography.supporting)
                            .foregroundStyle(NexusPalette.secondaryText)
                            .padding(.horizontal, NexusLayout.microSpacing)
                    }
                    metricsGrid
                    chartCard
                    historyCharts
                    infrastructureSummary
                    recentAlerts
                }
            }
            .padding(.horizontal, NexusLayout.screenInset)
            .padding(.bottom, 28)
            .frame(maxWidth: 880, alignment: .leading)
            .frame(maxWidth: .infinity)
            .background {
                GeometryReader { proxy in
                    Color.clear
                        .onAppear { contentWidth = proxy.size.width }
                        .onChange(of: proxy.size.width) { _, width in contentWidth = width }
                }
            }
        }
        .scrollIndicators(.hidden)
        .nexusScreenBackground()
        .toolbar(.hidden, for: .navigationBar)
        .task(id: "\(selectedDeviceID?.uuidString ?? "none")-\(automaticRefresh)-\(isActive)") {
            guard isActive, automaticRefresh else { return }
            while !Task.isCancelled {
                do { try await Task.sleep(for: .seconds(15)) }
                catch { return }
                guard !Task.isCancelled, scenePhase == .active,
                      let selectedDevice, snapshot != nil else { continue }
                store.refreshMetrics(for: selectedDevice)
            }
        }
        .onAppear {
            if selectedDeviceID == nil { selectedDeviceID = store.devices.first?.id }
        }
        .onChange(of: store.devices.map(\.id)) { _, ids in
            if let selectedDeviceID, !ids.contains(selectedDeviceID) { self.selectedDeviceID = ids.first }
            else if selectedDeviceID == nil { self.selectedDeviceID = ids.first }
        }
        .alert("Verify SSH host", isPresented: Binding(
            get: { store.pendingHostMetricsTrust != nil },
            set: { if !$0 { store.rejectMetricsHostKey() } }
        )) {
            Button("Trust and refresh") { store.approveMetricsHostKey() }
            Button("Cancel", role: .cancel) { store.rejectMetricsHostKey() }
        } message: {
            let pending = store.pendingHostMetricsTrust
            Text("\(pending?.device.name ?? "Server") · \(pending?.challenge.endpoint.authority ?? "")\n\(pending?.challenge.fingerprint ?? "")\nCompare this SHA256 fingerprint through a trusted channel before approving the server.")
        }
    }

    private var overviewSubtitle: String {
        "\(store.devices.count) device\(store.devices.count == 1 ? "" : "s") · \(status.title)"
    }

    /// The header's main action: measures the selected host.
    private var refreshButton: some View {
        Button {
            if let selectedDevice { store.refreshMetrics(for: selectedDevice) }
        } label: {
            if monitorState?.isRefreshing == true {
                ProgressView()
                    .frame(width: 44, height: 44)
                    .nexusGlass(cornerRadius: 22)
            } else {
                NexusRoundGlassLabel(systemImage: "arrow.clockwise")
            }
        }
        .buttonStyle(.plain)
        .disabled(monitorState?.isRefreshing == true)
        .accessibilityLabel(snapshot == nil ? "Check" : "Refresh")
        .accessibilityIdentifier("dashboard.metrics.first-refresh")
    }

    /// Only measured values appear here. Without a measured reply it says so.
    private var aiCard: some View {
        Button(action: onOpenAI) {
            NexusCard {
                VStack(alignment: .leading, spacing: 0) {
                    HStack(spacing: NexusLayout.compactSpacing) {
                        NexusStatusDot(color: NexusPalette.blue)
                        Text(aiSummary?.connectionName ?? "Nexus AI")
                            .font(NexusTypography.caption)
                            .foregroundStyle(NexusPalette.secondaryText)
                            .lineLimit(1)
                        Spacer(minLength: 0)
                        if let model = aiSummary?.modelName {
                            Text(model)
                                .font(NexusTypography.caption)
                                .foregroundStyle(NexusPalette.secondaryText)
                                .lineLimit(1)
                                .truncationMode(.middle)
                        }
                    }
                    Text(aiSummary?.speed ?? (aiSummary == nil ? "Not connected" : "No reply yet"))
                        .font(.title.weight(.bold).monospacedDigit())
                        .tracking(-0.4)
                        .foregroundStyle(NexusPalette.primaryText)
                        .padding(.top, 9)
                    Text(aiDetail)
                        .font(NexusTypography.supporting)
                        .foregroundStyle(NexusPalette.secondaryText)
                    if let fraction = aiSummary?.contextFraction {
                        GeometryReader { proxy in
                            Capsule().fill(.white.opacity(0.08))
                            Capsule().fill(NexusPalette.blue)
                                .frame(width: proxy.size.width * min(max(fraction, 0), 1))
                        }
                        .frame(height: 6)
                        .padding(.top, 9)
                    }
                }
            }
        }
        .buttonStyle(.plain)
        .accessibilityElement(children: .combine)
        .accessibilityHint("Opens AI chat")
    }

    private var aiDetail: String {
        guard let aiSummary else {
            return aiConnectionCount == 0 ? "Add an API connection in Settings" : "Open AI to choose a connection"
        }
        guard aiSummary.speed != nil else { return "Send a message to measure speed" }
        guard let fraction = aiSummary.contextFraction else { return "Last reply" }
        return "Last reply · \(Int((fraction * 100).rounded()))% of context used"
    }

    private var deviceSelectorLabel: some View {
        HStack(spacing: NexusLayout.compactSpacing + 2) {
            Image(systemName: "server.rack")
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(NexusPalette.blue)
            Text(selectedDevice?.name ?? "Choose a device")
                .font(NexusTypography.cardTitle)
                .foregroundStyle(NexusPalette.primaryText)
                .lineLimit(1)
            Spacer(minLength: 0)
            if store.devices.count > 1 {
                Image(systemName: "chevron.up.chevron.down")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(NexusPalette.secondaryText)
            }
        }
        .padding(.horizontal, NexusLayout.cardPadding)
        .frame(minHeight: 44)
        .background(NexusGlassSurface(cornerRadius: 22))
        .contentShape(Rectangle())
    }

    @ViewBuilder private var deviceSelector: some View {
        if store.devices.count == 1 {
            deviceSelectorLabel
                .accessibilityElement(children: .combine)
                .accessibilityIdentifier("dashboard.selected-device")
        } else {
            Menu {
                ForEach(store.devices) { device in
                    Button {
                        selectedDeviceID = device.id
                    } label: {
                        if device.id == selectedDevice?.id {
                            Label(device.name, systemImage: "checkmark")
                        } else {
                            Text(device.name)
                        }
                    }
                }
            } label: {
                deviceSelectorLabel
            }
            .buttonStyle(.plain)
            .accessibilityLabel("Monitored device: \(selectedDevice?.name ?? "none")")
        }
    }

    private var metricsGrid: some View {
        // Exyte Grid's GeometryReader reports ambiguous height inside the
        // scaling scroll view. On iPhone its charts overlapped later sections.
        // Native LazyVGrid participates in its parent's vertical layout.
        LazyVGrid(columns: metricColumns, alignment: .leading,
                  spacing: NexusLayout.standardSpacing) {
            NexusMetricCard(title: "CPU", value: percent(snapshot?.cpuUtilizationPercent),
                detail: store.isDemoMode ? "Preview sample" : (snapshot?.logicalCPUCount.map { "\($0) logical cores" } ?? ""),
                systemImage: "cpu", tint: NexusPalette.blue)
            NexusMetricCard(title: "Memory", value: percent(memoryUsedPercent),
                detail: memoryDetail, systemImage: "memorychip", tint: NexusPalette.purple)
            NexusMetricCard(title: "Storage", value: percent(storageUsedPercent),
                detail: storageDetail, systemImage: "internaldrive", tint: NexusPalette.green)
            NexusMetricCard(title: "Network", value: networkValue,
                detail: networkDetail, systemImage: "arrow.up.arrow.down", tint: NexusPalette.amber)
        }
        .accessibilityIdentifier("dashboard.telemetry-grid")
    }

    private var historyCharts: some View {
        Group {
            if contentWidth >= 720 && !dynamicTypeSize.isAccessibilitySize {
                HStack(alignment: .top, spacing: NexusLayout.standardSpacing) {
                    resourceTrendsCard
                    networkTrendsCard
                }
            } else {
                VStack(spacing: NexusLayout.standardSpacing) {
                    resourceTrendsCard
                    networkTrendsCard
                }
            }
        }
        .accessibilityIdentifier("dashboard.history-charts")
    }

    private var chartCard: some View {
        NexusCard {
            VStack(alignment: .leading, spacing: NexusLayout.compactSpacing) {
                NexusSectionHeader(title: "CPU activity", trailing: selectedDevice?.name)
                NexusCPUActivityChart(history: currentHistory)
                Toggle("Auto refresh · 15 sec", isOn: $automaticRefresh)
                    .font(NexusTypography.caption)
                    .foregroundStyle(NexusPalette.secondaryText)
                    .tint(NexusPalette.blue)
                if let observedAt = snapshot?.observedAt {
                    Text("Last sample \(observedAt, style: .relative) ago")
                        .font(.caption2).foregroundStyle(NexusPalette.secondaryText)
                }
            }
        }
    }

    private var resourceTrendsCard: some View {
        NexusCard {
            VStack(alignment: .leading, spacing: NexusLayout.standardSpacing) {
                NexusSectionHeader(title: "Memory & storage", subtitle: "Last 60 seconds · SSH samples")
                NexusResourceTrendsChart(history: currentHistory)
            }
        }
    }

    private var networkTrendsCard: some View {
        NexusCard {
            VStack(alignment: .leading, spacing: NexusLayout.standardSpacing) {
                NexusSectionHeader(title: "Network traffic", subtitle: "Measured intervals · Mb/s")
                if let selectedDevice {
                    NexusNetworkTrendsChart(history: currentHistory, deviceID: selectedDevice.id)
                } else {
                    ContentUnavailableView("No device selected", systemImage: "network")
                        .frame(height: 180)
                }
            }
        }
    }

    private var infrastructureSummary: some View {
        VStack(alignment: .leading, spacing: NexusLayout.standardSpacing) {
            NexusSectionHeader(title: "Infrastructure", subtitle: "Open a tool to check its current state")
            LazyVGrid(columns: (dynamicTypeSize.isAccessibilitySize || contentWidth < 330)
                ? [GridItem(.flexible(), spacing: NexusLayout.standardSpacing)]
                : [GridItem(.flexible(), spacing: NexusLayout.standardSpacing),
                   GridItem(.flexible(), spacing: NexusLayout.standardSpacing)],
                      spacing: NexusLayout.standardSpacing) {
                summaryAction(title: "Devices", detail: "\(store.devices.count) saved profiles", icon: "server.rack",
                    tint: NexusPalette.blue, action: onOpenDevices)
                summaryAction(title: "SSH sessions", detail: "\(connectedSessionCount) connected", icon: "terminal",
                    tint: NexusPalette.green, action: onOpenSessions)
                summaryAction(title: "AI", detail: aiConnectionCount == 0 ? "No enabled API profiles" : "\(aiConnectionCount) enabled API profile\(aiConnectionCount == 1 ? "" : "s")",
                    icon: "sparkles", tint: NexusPalette.purple, action: onOpenAI)
                summaryAction(title: "Services", detail: "Inspect systemd or game panel", icon: "gearshape.2",
                    tint: NexusPalette.amber, action: onOpenServices)
            }
        }
    }

    @ViewBuilder private var recentAlerts: some View {
        if let snapshot {
            VStack(alignment: .leading, spacing: NexusLayout.standardSpacing) {
                NexusSectionHeader(title: "Latest resource check", subtitle: "Based on the selected device's last SSH sample")
                if snapshot.lowResourceWarnings.isEmpty, snapshot.hasCompleteResourceWarningInputs {
                    NexusStatusBadge(title: "No low-resource warnings", systemImage: "checkmark.circle.fill", tone: .positive)
                } else if snapshot.lowResourceWarnings.isEmpty {
                    NexusStatusBadge(title: "Some resource readings unavailable", systemImage: "questionmark.circle", tone: .neutral)
                } else {
                    ForEach(snapshot.lowResourceWarnings, id: \.rawValue) { warning in
                        NexusStatusBadge(title: warning.rawValue.capitalized + " is low",
                            systemImage: "exclamationmark.triangle.fill", tone: .caution)
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func summaryAction(title: String, detail: String, icon: String, tint: Color,
                               action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(alignment: .top, spacing: NexusLayout.standardSpacing) {
                Image(systemName: icon).foregroundStyle(tint).frame(width: 24, height: 24)
                VStack(alignment: .leading, spacing: NexusLayout.microSpacing) {
                    Text(title).font(NexusTypography.cardTitle).foregroundStyle(NexusPalette.primaryText)
                    Text(detail).font(NexusTypography.supporting).foregroundStyle(NexusPalette.secondaryText)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 0)
                Image(systemName: "chevron.right").font(.caption.weight(.semibold)).foregroundStyle(NexusPalette.secondaryText)
            }
            .frame(maxWidth: .infinity, minHeight: 68, alignment: .leading)
            .contentShape(Rectangle())
            .nexusMatteSurface(padding: 14)
        }
        .buttonStyle(.plain)
        .accessibilityElement(children: .combine)
    }

    private var connectedSessionCount: Int {
        store.sessions.filter { $0.state == .connected }.count
    }

    private var memoryDetail: String {
        guard let total = snapshot?.memoryTotalBytes, let available = snapshot?.memoryAvailableBytes,
              total > 0, available <= total else { return "" }
        return "\(formatBytes(total - available)) of \(formatBytes(total))"
    }

    private var storageDetail: String {
        guard let filesystem = snapshot?.rootFilesystem,
              filesystem.totalBytes > 0, filesystem.usedBytes <= filesystem.totalBytes else { return "" }
        return "\(formatBytes(filesystem.usedBytes)) of \(formatBytes(filesystem.totalBytes))"
    }

    private var networkValue: String? {
        guard let rates = networkRates else { return nil }
        return "↓ \(formatRate(rates.download))"
    }

    private var networkDetail: String {
        guard let rates = networkRates else { return snapshot == nil ? "" : "Refresh again to measure" }
        return "↑ \(formatRate(rates.upload)) average"
    }

    private func percent(_ value: Double?) -> String? {
        guard let value, value.isFinite, (0...100).contains(value) else { return nil }
        return "\(value.formatted(.number.precision(.fractionLength(0))))%"
    }

    private func formatBytes(_ value: UInt64) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(clamping: value), countStyle: .memory)
    }

    private func formatRate(_ bytesPerSecond: Double) -> String {
        guard bytesPerSecond.isFinite, bytesPerSecond >= 0 else { return "Unavailable" }
        let count = bytesPerSecond >= Double(Int64.max) ? Int64.max : Int64(bytesPerSecond)
        return ByteCountFormatter.string(fromByteCount: count, countStyle: .memory) + "/s"
    }
}

private struct HostMetricsCard: View {
    let device: Device
    let state: HostMonitorState
    let history: [HostMetricsHistoryRecord]
    let refresh: () -> Void

    private var currentEndpointHistory: [HostMetricsHistoryRecord] {
        guard let sourceEndpoint = state.sourceEndpoint else { return [] }
        return history.filter {
            $0.belongs(to: device) && $0.endpoint.authority == sourceEndpoint.authority
        }
    }

    private var networkRates: [HostNetworkRate] {
        HostNetworkRateCalculator.rates(for: device.id, in: currentEndpointHistory)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: NexusLayout.standardSpacing) {
            HStack(alignment: .top) {
                Text(device.name)
                    .font(.headline)
                    .fixedSize(horizontal: false, vertical: true)
                    .layoutPriority(1)
                Spacer(minLength: 8)
                if state.isRefreshing { ProgressView().controlSize(.small) }
                Button("Refresh", systemImage: "arrow.clockwise", action: refresh)
                    .labelStyle(.iconOnly)
                    .frame(minWidth: 44, minHeight: 44)
                    .disabled(state.isRefreshing)
                    .accessibilityLabel("Refresh host status for \(device.name)")
                    .accessibilityIdentifier("dashboard.metrics.refresh.\(device.username)")
            }

            if let snapshot = state.snapshot {
                HStack(spacing: 5) {
                    Text("Last sampled \(snapshot.observedAt, style: .relative) ago")
                    if let endpoint = state.sourceEndpoint { Text("· \(endpoint.host)") }
                }
                .font(.caption).foregroundStyle(.secondary)

                let warnings = lowResourceWarnings(snapshot)
                if warnings.isEmpty {
                    if snapshot.hasCompleteResourceWarningInputs {
                        NexusStatusBadge(title: "Disk and memory meet low-resource thresholds",
                            systemImage: "checkmark.circle", tone: .positive)
                    } else {
                        NexusStatusBadge(title: "Disk or memory readings unavailable",
                            systemImage: "questionmark.circle", tone: .neutral)
                    }
                } else {
                    ForEach(warnings, id: \.self) { warning in
                        NexusStatusBadge(title: warning, systemImage: "exclamationmark.triangle.fill",
                            tone: .caution)
                    }
                }

                metric("Uptime", value: snapshot.uptimeSeconds.map(formatUptime) ?? "Unavailable")
                metric("CPU load (1 / 5 / 15 min)", value: snapshot.loadAverage.map {
                    String(format: "%.2f / %.2f / %.2f", $0.oneMinute, $0.fiveMinutes, $0.fifteenMinutes)
                } ?? "Unavailable")
                metric("CPU utilization", value: snapshot.cpuUtilizationPercent.map { String(format: "%.1f%%", $0) } ?? "Unavailable")
                metric("Logical CPUs", value: snapshot.logicalCPUCount.map { String($0) } ?? "Unavailable")
                metric("Memory available", value: memorySummary(snapshot.memoryAvailableBytes, total: snapshot.memoryTotalBytes))
                metric("Root filesystem", value: filesystemSummary(snapshot.rootFilesystem))
                metric("NVIDIA telemetry", value: snapshot.nvidiaSMIAvailable
                    ? (snapshot.nvidiaGPUs.isEmpty ? "Tool found; no valid device readings" : "Available")
                    : "nvidia-smi unavailable")
                ForEach(snapshot.nvidiaGPUs) { gpu in
                    metric("GPU \(gpu.index) utilization", value: gpu.utilizationPercent.map { String(format: "%.1f%%", $0) } ?? "Unavailable")
                    metric("GPU \(gpu.index) memory", value: gpuMemorySummary(gpu))
                    metric("GPU \(gpu.index) temperature", value: gpu.temperatureCelsius.map { String(format: "%.0f°C", $0) } ?? "Unavailable")
                }

                if snapshot.networkInterfaces.isEmpty {
                    metric("Network", value: "No non-loopback interface data")
                } else {
                    ForEach(snapshot.networkInterfaces) { interface in
                        metric("\(interface.interface) · RX / TX", value:
                            "\(formatBytes(interface.receivedBytes)) / \(formatBytes(interface.transmittedBytes))")
                    }
                }
                if networkRates.isEmpty {
                    metric("Average network throughput", value: currentEndpointHistory.count < 2
                        ? "Refresh again to calculate a rate"
                        : "Unavailable between the latest samples")
                } else {
                    ForEach(networkRates) { rate in
                        metric("\(rate.interface) · average RX / TX over \(formatInterval(rate.intervalSeconds))",
                            value: "\(formatNetworkRate(rate.receivedBytesPerSecond)) / \(formatNetworkRate(rate.transmittedBytesPerSecond))")
                    }
                }
                if let error = state.error {
                    Label("Showing last successful snapshot. \(error)", systemImage: "exclamationmark.triangle.fill")
                        .font(.caption).foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                }
            } else if state.isRefreshing {
                Text("Connecting securely and collecting read-only Linux status…")
                    .font(.caption).foregroundStyle(.secondary)
            } else if let error = state.error {
                Label(error, systemImage: "network.slash")
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                Text("Tap Refresh to collect a live SSH snapshot.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            if currentEndpointHistory.count >= 2 { historyChart }
            if let historyError = state.historyError {
                Label(historyError, systemImage: "externaldrive.badge.exclamationmark")
                    .font(.caption).foregroundStyle(.orange)
            }
        }
    }

    private func metric(_ title: String, value: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title)
                .font(.caption)
                .foregroundStyle(.secondary)
            Text(value)
                .font(.subheadline)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
        .accessibilityElement(children: .combine)
    }

    private var historyChart: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Recent CPU and memory")
                .font(.caption).foregroundStyle(.secondary)
            Chart(currentEndpointHistory) { record in
                if let cpu = record.snapshot.cpuUtilizationPercent {
                    LineMark(x: .value("Time", record.snapshot.observedAt),
                        y: .value("Percent", cpu))
                        .foregroundStyle(by: .value("Metric", "CPU"))
                }
                if let total = record.snapshot.memoryTotalBytes,
                   let available = record.snapshot.memoryAvailableBytes, total > 0,
                   available <= total {
                    let usedPercent = Double(total - available) / Double(total) * 100
                    LineMark(x: .value("Time", record.snapshot.observedAt),
                        y: .value("Percent", usedPercent))
                        .foregroundStyle(by: .value("Metric", "Memory"))
                }
            }
            .chartYScale(domain: 0...100)
            .chartYAxisLabel("Percent")
            .chartLegend(position: .bottom, alignment: .leading)
            .frame(height: 150)
            Text("Added only when you refresh · retained up to 30 days or 500 samples per device")
                .font(.caption2).foregroundStyle(.tertiary)
        }
        .accessibilityElement(children: .contain)
    }

    private func formatUptime(_ seconds: Double) -> String {
        let total = Int(seconds)
        let days = total / 86_400
        let hours = (total % 86_400) / 3_600
        let minutes = (total % 3_600) / 60
        return days > 0 ? "\(days)d \(hours)h \(minutes)m" : "\(hours)h \(minutes)m"
    }

    private func memorySummary(_ available: UInt64?, total: UInt64?) -> String {
        guard let available, let total else { return "Unavailable" }
        return "\(formatBytes(available)) available of \(formatBytes(total))"
    }

    private func lowResourceWarnings(_ snapshot: HostMetricsSnapshot) -> [String] {
        snapshot.lowResourceWarnings.map { warning -> String in
            switch warning {
            case .rootFilesystemLow:
                guard let filesystem = snapshot.rootFilesystem else { return "Low root disk space at last sample" }
                let percent = Double(filesystem.availableBytes) / Double(filesystem.totalBytes) * 100
                return String(format: "Root disk %.1f%% free at last sample", percent)
            case .memoryLow:
                guard let total = snapshot.memoryTotalBytes,
                      let available = snapshot.memoryAvailableBytes else { return "Low memory at last sample" }
                let percent = Double(available) / Double(total) * 100
                return String(format: "Memory %.1f%% available at last sample", percent)
            }
        }
    }

    private func filesystemSummary(_ usage: HostFilesystemUsage?) -> String {
        guard let usage else { return "Unavailable" }
        return "\(formatBytes(usage.usedBytes)) used of \(formatBytes(usage.totalBytes)) · \(formatBytes(usage.availableBytes)) free"
    }

    private func gpuMemorySummary(_ gpu: HostGPUUsage) -> String {
        guard let used = gpu.memoryUsedMiB, let total = gpu.memoryTotalMiB else { return "Unavailable" }
        return "\(used) MiB used of \(total) MiB"
    }

    private func formatBytes(_ value: UInt64) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(clamping: value), countStyle: .memory)
    }

    private func formatNetworkRate(_ bytesPerSecond: Double) -> String {
        guard bytesPerSecond.isFinite, bytesPerSecond >= 0 else { return "Unavailable" }
        let count: Int64
        if bytesPerSecond >= Double(Int64.max) { count = Int64.max }
        else { count = Int64(bytesPerSecond.rounded(.down)) }
        return ByteCountFormatter.string(fromByteCount: count, countStyle: .memory) + "/s"
    }

    private func formatInterval(_ seconds: TimeInterval) -> String {
        if seconds < 60 { return "\(Int(max(1, seconds.rounded()))) sec" }
        let minutes = seconds / 60
        if minutes < 60 { return "\(Int(minutes.rounded())) min" }
        return "\(Int((minutes / 60).rounded())) hr"
    }
}

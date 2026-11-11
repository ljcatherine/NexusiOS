#if NEXUS_DEMO_MODE
import SwiftUI

/// Appetize/Simulator entry point. It shares the production SwiftUI navigation and screens while
/// injecting an isolated sample store. Demo-mode guards prevent real credential, filesystem,
/// notification, and network access.
@main
struct NexusDemoApp: App {
    @State private var store = AppStore(demoMode: true)

    var body: some Scene {
        WindowGroup {
            RootView(store: store)
                .dynamicTypeSize(.xLarge ... .accessibility5)
                .preferredColorScheme(.dark)
        }
    }
}

private enum DemoPalette {
    static let accent = Color.cyan
    static let positive = Color.green
}

struct NexusDemoManageView: View {
    var body: some View {
        List {
            Section("Server tools · simulated") {
                NavigationLink(value: ManagementRoute.devices) { Label("Devices", systemImage: "server.rack") }
                    .accessibilityIdentifier("manage.devices")
                NavigationLink(destination: DemoServicesView()) { Label("System services", systemImage: "gearshape.2") }
                NavigationLink(destination: DemoFilesView()) { Label("Files", systemImage: "folder") }
                NavigationLink(destination: DemoMinecraftView()) { Label("Minecraft servers", systemImage: "gamecontroller") }
                NavigationLink(destination: DemoNetworkView()) { Label("Network diagnostics", systemImage: "network") }
                NavigationLink(destination: DemoRecipesView()) { Label("Command recipes", systemImage: "terminal") }
            }
            Section {
                Text("These screens use local sample state only. No SSH, filesystem, panel, or network APIs are called.")
                    .font(.footnote).foregroundStyle(.secondary)
            }
        }
        .listStyle(.insetGrouped)
        .navigationTitle("Manage")
    }
}

private struct DemoServicesView: View {
    @State private var activeServices: Set<String> = ["SSH", "Vanilla Minecraft"]
    @State private var lastAction: String?
    private let services = ["SSH", "Vanilla Minecraft", "SkyFactory Minecraft"]

    var body: some View {
        List {
            Section("Service status · sample") {
                ForEach(services, id: \.self) { service in
                    HStack {
                        VStack(alignment: .leading, spacing: 4) {
                            Text(service).font(.headline)
                            NexusStatusBadge(title: activeServices.contains(service) ? "Running · sample" : "Stopped · sample",
                                systemImage: activeServices.contains(service) ? "checkmark.circle.fill" : "stop.circle",
                                tone: activeServices.contains(service) ? .positive : .neutral)
                        }
                        Spacer()
                        if activeServices.contains(service) {
                            Button("Restart", systemImage: "arrow.clockwise") {
                                activeServices.insert(service)
                                lastAction = "\(service) restarted · simulated"
                            }
                                .labelStyle(.iconOnly).accessibilityLabel("Restart simulated \(service)")
                            Button("Stop", systemImage: "stop.fill") {
                                activeServices.remove(service)
                                lastAction = "\(service) stopped · simulated"
                            }
                                .labelStyle(.iconOnly).accessibilityLabel("Stop simulated \(service)")
                        } else {
                            Button("Start", systemImage: "play.fill") {
                                activeServices.insert(service)
                                lastAction = "\(service) started · simulated"
                            }
                                .labelStyle(.iconOnly).accessibilityLabel("Start simulated \(service)")
                        }
                    }
                    .padding(.vertical, 4)
                }
            }
            if let lastAction {
                Section("Most recent action") {
                    NexusStatusBadge(title: lastAction, systemImage: "checkmark.circle", tone: .neutral)
                }
            }
            Section {
                Text("Service controls change only this preview's sample state. No command is sent to a server.")
                    .font(.footnote).foregroundStyle(.secondary)
            }
        }
        .listStyle(.insetGrouped)
        .navigationTitle("Services")
        .navigationBarTitleDisplayMode(.inline)
    }
}

private struct DemoFilesView: View {
    var body: some View {
        List {
            Section("Home · sample files") {
                Label("Documents", systemImage: "folder.fill")
                Label("Backups", systemImage: "folder.fill")
                Label("server.properties", systemImage: "doc.text")
                Label("README.txt", systemImage: "doc.text")
            }
            Section {
                Label("Read-only preview", systemImage: "eye")
                Text("Names and sizes are fictional. Upload, download, and edit are disabled in this demo.")
                    .font(.footnote).foregroundStyle(.secondary)
            }
        }
        .listStyle(.insetGrouped)
        .navigationTitle("Files")
        .navigationBarTitleDisplayMode(.inline)
    }
}

private struct DemoMinecraftView: View {
    @State private var isRunning = true
    @State private var lastAction: String?

    var body: some View {
        List {
            Section("Minecraft · sample instance") {
                LabeledContent("Vanilla", value: "Minecraft Java")
                NexusStatusBadge(title: isRunning ? "Running · simulated" : "Stopped · simulated",
                    systemImage: isRunning ? "checkmark.circle.fill" : "stop.circle",
                    tone: isRunning ? .positive : .neutral)
                LabeledContent("Players", value: isRunning ? "3 / 20 · sample" : "0 / 20 · sample")
                LabeledContent("Uptime", value: isRunning ? "4 days · sample" : "Stopped")
            }
            Section("Preview controls") {
                Button(isRunning ? "Stop sample server" : "Start sample server",
                    systemImage: isRunning ? "stop.fill" : "play.fill") {
                    isRunning.toggle()
                    lastAction = isRunning ? "Started · simulated" : "Stopped · simulated"
                }
                Button("Restart sample server", systemImage: "arrow.clockwise") {
                    isRunning = true
                    lastAction = "Restarted · simulated"
                }
                    .disabled(!isRunning)
                if let lastAction { Text(lastAction).font(.caption).foregroundStyle(.secondary) }
                Text("These buttons only update local sample state. The private Debian Homelab Panel is not loaded and no action is sent.")
                    .font(.footnote).foregroundStyle(.secondary)
            }
        }
        .listStyle(.insetGrouped)
        .navigationTitle("Minecraft")
        .navigationBarTitleDisplayMode(.inline)
    }
}

private struct DemoNetworkView: View {
    @State private var checked = false
    @State private var checkedAt: Date?

    var body: some View {
        List {
            Section {
                Text("Run an example endpoint check to preview the result layout. This does not scan or contact the local network.")
                    .font(.footnote).foregroundStyle(.secondary)
                Button("Check sample endpoints", systemImage: "dot.radiowaves.left.and.right") {
                    checked = true
                    checkedAt = .now
                }
            } header: { Text("Network diagnostics · simulated") }
            if checked {
                Section("Saved endpoint samples") {
                    Label("NixOS Workstation · reachable sample", systemImage: "checkmark.circle.fill")
                        .foregroundStyle(DemoPalette.positive)
                    Label("Debian Homelab Server · reachable sample", systemImage: "checkmark.circle.fill")
                        .foregroundStyle(DemoPalette.positive)
                    if let checkedAt {
                        LabeledContent("Sample checked", value: checkedAt.formatted(date: .omitted, time: .shortened))
                    }
                }
            }
            Section {
                Text("Reachability samples do not verify credentials, host keys, or server identity.")
                    .font(.footnote).foregroundStyle(.secondary)
            }
        }
        .listStyle(.insetGrouped)
        .navigationTitle("Network")
        .navigationBarTitleDisplayMode(.inline)
    }
}

private struct DemoRecipesView: View {
    @State private var lastResult: String?

    var body: some View {
        List {
            Section("Saved examples") {
                recipe("Show system uptime", command: "uptime")
                recipe("Check disk space", command: "df -h /")
                recipe("List active services", command: "systemctl --type=service --state=running")
            }
            if let lastResult {
                Section("Simulated result") {
                    Text(lastResult).font(.system(.footnote, design: .monospaced)).textSelection(.enabled)
                }
            }
            Section {
                Text("Running a recipe displays a canned preview response. No command is executed.")
                    .font(.footnote).foregroundStyle(.secondary)
            }
        }
        .listStyle(.insetGrouped)
        .navigationTitle("Recipes")
        .navigationBarTitleDisplayMode(.inline)
    }

    private func recipe(_ title: String, command: String) -> some View {
        VStack(alignment: .leading, spacing: 7) {
            Text(title).font(.headline)
            Text(command).font(.caption.monospaced()).foregroundStyle(.secondary)
            Button("Preview sample result", systemImage: "play.fill") {
                lastResult = "$ \(command)\nSample response · simulated output only"
            }
            .font(.subheadline)
        }
        .padding(.vertical, 4)
    }
}

#endif

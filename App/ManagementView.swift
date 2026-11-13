import SwiftUI
import NexusCore

struct ServicesHomeView: View {
    @Bindable var store: AppStore

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: NexusLayout.sectionSpacing) {
                NexusScreenHeader(title: "Services", subtitle: "Manage your hosts and connected services")
                NexusGlassGroup {
                    toolLink("System services", symbol: "gearshape.2", tint: NexusPalette.blue,
                             detail: "Systemd, processes, logs, and confirmed controls") {
                        ServicesView(store: store)
                    }
                    NexusGlassDivider()
                    toolLink("Files", symbol: "folder", tint: NexusPalette.amber,
                             detail: "Browse and transfer files over SFTP") {
                        FilesView(store: store)
                    }
                    NexusGlassDivider()
                    toolLink("Network", symbol: "network", tint: NexusPalette.purple,
                             detail: "Discover SSH services and check saved endpoints") {
                        NetworkDiagnosticsView(store: store)
                    }
                    NexusGlassDivider()
                    toolLink("Command recipes", symbol: "text.book.closed", tint: NexusPalette.blue,
                             detail: "Preview and confirm saved commands") {
                        RecipesView(store: store)
                    }
                    NexusGlassDivider()
                    toolLink("One Time Passcode", symbol: "key.viewfinder", tint: NexusPalette.green,
                             detail: "4-digit code that unlocks Nexus Desktop on Windows") {
                        OneTimePasscodeView(store: store)
                    }
                }
                NexusCard {
                    Label("SSH host keys stay verified. Service and configuration changes keep their confirmation steps.",
                          systemImage: "lock.shield")
                        .font(NexusTypography.supporting)
                        .foregroundStyle(NexusPalette.secondaryText)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .padding(.horizontal, NexusLayout.screenInset)
            .padding(.bottom, NexusLayout.standardSpacing)
            .frame(maxWidth: 760, alignment: .leading)
            .frame(maxWidth: .infinity)
        }
        .scrollIndicators(.hidden)
        .nexusScreenBackground()
        .toolbar(.hidden, for: .navigationBar)
    }

    private func toolLink<Destination: View>(_ title: String, symbol: String, tint: Color, detail: String,
        @ViewBuilder destination: () -> Destination) -> some View {
        NavigationLink(destination: destination) {
            HStack(spacing: NexusLayout.standardSpacing) {
                NexusIconTile(systemImage: symbol, tint: tint)
                VStack(alignment: .leading, spacing: 2) {
                    Text(title).font(NexusTypography.cardTitle).foregroundStyle(NexusPalette.primaryText)
                    Text(detail).font(NexusTypography.caption).foregroundStyle(NexusPalette.secondaryText)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 0)
                Image(systemName: "chevron.right").font(.caption.weight(.semibold)).foregroundStyle(NexusPalette.secondaryText)
            }
            .padding(.horizontal, NexusLayout.cardPadding)
            .padding(.vertical, 12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityElement(children: .combine)
    }
}

struct ManagementView: View {
    @Bindable var store: AppStore

    var body: some View {
        #if NEXUS_DEMO_MODE
        if store.isDemoMode {
            NexusDemoManageView()
        } else {
            productionManagementView
        }
        #else
        productionManagementView
        #endif
    }

    private var productionManagementView: some View {
        NexusList {
            Section("Host administration") {
                NavigationLink(value: ManagementRoute.devices) {
                    toolRow("Devices", symbol: "server.rack", detail: "Edit SSH profiles and open terminals")
                }
                .accessibilityIdentifier("manage.devices")
                NavigationLink {
                    ServicesView(store: store)
                } label: {
                    toolRow("Services", symbol: "gearshape.2",
                        detail: "Systemd state, logs, processes, and confirmed controls")
                }
                NavigationLink {
                    FilesView(store: store)
                } label: {
                    toolRow("Files", symbol: "folder",
                        detail: "Two-sided SFTP browser, transfers, and remote file actions")
                }
            }

            Section("Connectivity") {
                NavigationLink {
                    NetworkDiagnosticsView(store: store)
                } label: {
                    toolRow("Network", symbol: "network",
                        detail: "Bonjour discovery and saved endpoint checks")
                }
            }

            Section("Automation") {
                NavigationLink {
                    RecipesView(store: store)
                } label: {
                    toolRow("Command recipes", symbol: "text.book.closed",
                        detail: "Preview and confirm saved commands")
                }
            }

            Section {
                Text("Remote changes require confirmation. SSH host keys remain individually verified; network discovery and reachability checks do not establish a host's identity.")
                    .font(.footnote).foregroundStyle(.secondary)
            }
        }
        .navigationTitle("Manage")
    }

    private func toolRow(_ title: String, symbol: String, detail: String) -> some View {
        Label {
            VStack(alignment: .leading, spacing: NexusLayout.compactSpacing / 2) {
                Text(title).font(.body)
                Text(detail).font(.caption).foregroundStyle(.secondary)
            }
        } icon: {
            Image(systemName: symbol).frame(width: 26)
        }
        .padding(.vertical, 3)
        .accessibilityElement(children: .combine)
    }
}

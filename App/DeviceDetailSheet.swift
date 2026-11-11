import SwiftUI
import NexusCore

/// A device summary that presents over the current tab without replacing its
/// NavigationStack. The caller performs terminal navigation after dismissal so
/// the SSH trust challenge and connection error remain in the terminal screen.
struct DeviceDetailSheet: View {
    @Bindable var store: AppStore
    let deviceID: UUID
    let onOpenTerminal: (Device) -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var editing: Device?

    private var device: Device? {
        store.devices.first { $0.id == deviceID }
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                if let device {
                    VStack(alignment: .leading, spacing: NexusLayout.sectionSpacing) {
                        DeviceDetailGlassCard {
                            HStack(alignment: .top, spacing: 12) {
                                Image(systemName: "server.rack")
                                    .font(.title2)
                                    .foregroundStyle(NexusPalette.blue)
                                    .frame(width: 44, height: 44)
                                    .background(NexusPalette.blue.opacity(0.12), in: RoundedRectangle(cornerRadius: 12))
                                    .accessibilityHidden(true)
                                VStack(alignment: .leading, spacing: 6) {
                                    Text(device.name)
                                        .font(.title3.weight(.semibold))
                                        .foregroundStyle(NexusPalette.primaryText)
                                    LabeledContent("SSH user", value: device.username)
                                        .font(.subheadline)
                                        .foregroundStyle(NexusPalette.secondaryText)
                                }
                            }
                        }

                        VStack(spacing: 10) {
                            Button {
                                onOpenTerminal(device)
                            } label: {
                                Label("Open terminal", systemImage: "terminal")
                                    .frame(maxWidth: .infinity, minHeight: 44)
                            }
                            .buttonStyle(.borderedProminent)
                            .accessibilityIdentifier("device.detail.open-terminal")

                            Button {
                                editing = device
                            } label: {
                                Label("Edit device", systemImage: "pencil")
                                    .frame(maxWidth: .infinity, minHeight: 44)
                            }
                            .buttonStyle(.bordered)
                            .accessibilityIdentifier("device.detail.edit")

                            Button {
                                store.toggleFavorite(device)
                            } label: {
                                Label(store.favoriteDeviceIDs.contains(device.id)
                                    ? "Remove from favorites" : "Add to favorites",
                                    systemImage: store.favoriteDeviceIDs.contains(device.id) ? "star.slash" : "star")
                                    .frame(maxWidth: .infinity, minHeight: 44)
                            }
                            .buttonStyle(.bordered)
                            .accessibilityIdentifier("device.detail.favorite")
                        }

                        VStack(alignment: .leading, spacing: 10) {
                            Text("Connection endpoints")
                                .font(NexusTypography.sectionTitle)
                                .foregroundStyle(NexusPalette.primaryText)
                            ForEach(device.orderedEndpoints) { endpoint in
                                DeviceDetailGlassCard {
                                    VStack(alignment: .leading, spacing: 6) {
                                        Text(endpoint.host)
                                            .font(.subheadline.weight(.semibold))
                                            .foregroundStyle(NexusPalette.primaryText)
                                            .textSelection(.enabled)
                                        Text("\(endpoint.kind.rawValue.capitalized) · Port \(endpoint.port) · Priority \(endpoint.priority)")
                                            .font(.subheadline)
                                            .foregroundStyle(NexusPalette.secondaryText)
                                        if let target = endpoint.relayTarget {
                                            Text("SSH relay target: \(target)")
                                                .font(.caption)
                                                .foregroundStyle(NexusPalette.secondaryText)
                                        }
                                    }
                                }
                            }
                        }

                        let sessions = store.sessions.filter { $0.device.id == device.id }
                        DeviceDetailGlassCard {
                            Label("Terminal sessions", systemImage: "terminal")
                                .font(NexusTypography.cardTitle)
                            Text(sessions.isEmpty
                                ? "No sessions opened for this device."
                                : "\(sessions.count) session\(sessions.count == 1 ? "" : "s") opened for this device.")
                                .font(.subheadline)
                                .foregroundStyle(NexusPalette.secondaryText)
                            Text("Connections are checked when you open a session. Host-key verification remains required.")
                                .font(.footnote)
                                .foregroundStyle(NexusPalette.secondaryText)
                        }
                    }
                    .padding(NexusLayout.screenInset)
                    .frame(maxWidth: 760)
                    .frame(maxWidth: .infinity)
                } else {
                    ContentUnavailableView("Device no longer exists", systemImage: "server.rack",
                        description: Text("Close this sheet to return to the saved devices."))
                        .padding()
                }
            }
            .navigationTitle("Device details")
            .navigationBarTitleDisplayMode(.inline)
            .background(NexusPalette.background.opacity(0.2).ignoresSafeArea())
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Done") { dismiss() }
                        .frame(minHeight: 44)
                        .accessibilityIdentifier("device.detail.done")
                }
            }
        }
        .presentationDetents([.medium, .large])
        .presentationDragIndicator(.visible)
        .presentationBackground(.regularMaterial)
        .presentationContentInteraction(.scrolls)
        .sheet(item: $editing) { current in
            NavigationStack { DeviceEditor(store: store, device: current) }
                .presentationDetents([.large])
                .presentationDragIndicator(.visible)
        }
    }
}

private struct DeviceDetailGlassCard<Content: View>: View {
    @ViewBuilder let content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            content
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(NexusGlassSurface(cornerRadius: 22))
    }
}

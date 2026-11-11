import SwiftUI
import UIKit
import SwiftTerm
import NexusCore
import NexusSSH

struct SessionsView: View {
    @Bindable var store: AppStore
    let onOpen: (Device) -> Void
    var body: some View {
        NexusList {
            ForEach(store.sessions) { session in
                NavigationLink(value: session.id) {
                    VStack(alignment: .leading) {
                        Text(session.device.name).font(.headline)
                        HStack(spacing: NexusLayout.compactSpacing) {
                            sessionStateBadge(session.state)
                            Text(session.endpoint?.host ?? "Selecting endpoint")
                                .font(.caption.monospaced()).foregroundStyle(.secondary).lineLimit(1)
                        }
                    }
                }
                .swipeActions { Button("Close", role: .destructive) { store.close(session) } }
            }
            Section("New session") {
                ForEach(store.devices) { device in
                    Button(device.name, systemImage: "plus") { onOpen(device) }
                        .accessibilityIdentifier("session.new-terminal")
                }
            }
        }
        .navigationTitle("Terminal")
        .overlay {
            if store.devices.isEmpty { ContentUnavailableView("Add a device", systemImage: "server.rack", description: Text("Save a connection in Devices to open a terminal.")) }
        }
    }
}

private func sessionStateBadge(_ state: SessionState) -> some View {
    let values: (String, String, NexusStatusTone) = switch state {
    case .connected: ("Connected", "checkmark.circle.fill", .positive)
    case .connecting: ("Connecting", "arrow.clockwise", .caution)
    case .verifyingHost: ("Verify host", "lock.shield", .caution)
    case .failed: ("Failed", "xmark.circle.fill", .critical)
    case .disconnected: ("Disconnected", "minus.circle", .neutral)
    }
    return NexusStatusBadge(title: values.0, systemImage: values.1, tone: values.2)
}

struct TerminalScreen: View {
    @Bindable var session: TerminalSession
    let fontSize: Double
    let onEditExampleDevice: () -> Void
    @State private var searching = false
    @State private var search = ""
    @State private var snapshot = ""
    @State private var controlModifierActive = false
    @State private var metaModifierActive = false
    @State private var sessionFontSize: Double?
    var body: some View {
        VStack(spacing: 0) {
            HStack {
                sessionStateBadge(session.state)
                Spacer()
                Text(session.endpoint?.authority ?? "").font(.caption.monospaced()).lineLimit(1)
            }.padding(10).background(.bar)
            if session.state == .connecting, let stage = session.connectionStage {
                HStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    Text(stage.title).font(.caption).foregroundStyle(.secondary)
                    Spacer(minLength: 0)
                }
                .padding(.horizontal, 12).padding(.vertical, 6)
                .accessibilityIdentifier("terminal.connection-stage")
            }
            if let error = session.error {
                VStack(alignment: .leading, spacing: 8) {
                    Text(error).font(.caption).foregroundStyle(.red)
                    if session.state == .failed, let stage = session.failureStage {
                        Text("Nexus reached this step before the connection failed: \(stage.title).")
                            .font(.caption).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    if session.state == .failed, let diagnostic = session.failureDiagnostic {
                        Text("Diagnostic: \(diagnostic)")
                            .font(.caption2.monospaced()).foregroundStyle(.secondary)
                            .textSelection(.enabled)
                            .fixedSize(horizontal: false, vertical: true)
                        Button("Copy diagnostic", systemImage: "doc.on.doc") {
                            UIPasteboard.general.string = diagnostic
                        }
                        .font(.caption)
                        .accessibilityIdentifier("terminal.copy-ssh-diagnostic")
                    }
                    if session.state == .failed,
                       session.error == SSHFailure.connectionFailed.localizedDescription {
                        Text("If this is a local address, check Nexus has Local Network access in iPhone Settings. For Tailscale addresses, connect the Tailscale app first.")
                            .font(.caption).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                        Button("Open Nexus Settings", systemImage: "gearshape") {
                            guard let url = URL(string: UIApplication.openSettingsURLString) else { return }
                            UIApplication.shared.open(url)
                        }
                        .accessibilityIdentifier("terminal.open-app-settings")
                    }
                    if session.state == .failed, session.endpoint?.isExampleAddress == true {
                        Text("This is a sample profile. Add the computer's current address and SSH username in Devices before reconnecting.")
                            .font(.caption).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                        Button("Go to Devices", systemImage: "server.rack", action: onEditExampleDevice)
                            .accessibilityIdentifier("terminal.edit-example-profile")
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(8)
            }
            TerminalRepresentable(session: session, fontSize: sessionFontSize ?? fontSize)
            HStack(spacing: 0) {
                Button("Hide keyboard", systemImage: "keyboard.chevron.compact.down") {
                    session.terminal.resignFirstResponder()
                }
                .labelStyle(.iconOnly)
                .frame(width: 44, height: 44)
                .accessibilityIdentifier("terminal.hide-keyboard")
                Menu {
                    Button("Fit more text", systemImage: "arrow.down.right.and.arrow.up.left") {
                        sessionFontSize = 9
                    }
                    Button("Smaller text", systemImage: "minus.magnifyingglass") {
                        sessionFontSize = max(8, (sessionFontSize ?? fontSize) - 1)
                    }
                    .disabled((sessionFontSize ?? fontSize) <= 8)
                    Button("Larger text", systemImage: "plus.magnifyingglass") {
                        sessionFontSize = min(26, (sessionFontSize ?? fontSize) + 1)
                    }
                    .disabled((sessionFontSize ?? fontSize) >= 26)
                    Button("Use settings size") { sessionFontSize = nil }
                } label: {
                    Image(systemName: "textformat.size").frame(width: 44, height: 44)
                }
                .accessibilityLabel("Terminal text size")
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 8) {
                    key("sudo", bytes: "sudo ")
                    key("ESC", bytes: "\u{1B}")
                    key("TAB", bytes: "\t")
                    Button(controlModifierActive ? "CTRL ✓" : "CTRL") {
                        session.terminal.controlModifier.toggle()
                        controlModifierActive = session.terminal.controlModifier
                        session.terminal.becomeFirstResponder()
                    }
                    .frame(minWidth: 60, minHeight: 44)
                    .tint(controlModifierActive ? .orange : .accentColor)
                    .accessibilityLabel("Control modifier")
                    .accessibilityValue(controlModifierActive ? "On" : "Off")
                    Button(metaModifierActive ? "ALT ✓" : "ALT") {
                        session.terminal.metaModifier.toggle()
                        metaModifierActive = session.terminal.metaModifier
                        session.terminal.becomeFirstResponder()
                    }
                    .frame(minWidth: 60, minHeight: 44)
                    .tint(metaModifierActive ? .orange : .accentColor)
                    .accessibilityLabel("Option modifier")
                    .accessibilityValue(metaModifierActive ? "On" : "Off")
                    arrow("↑", suffix: "A"); arrow("↓", suffix: "B")
                    arrow("←", suffix: "D"); arrow("→", suffix: "C")
                    ForEach(["/", "|", "~", "-"], id: \.self) { value in
                        Button(value) { session.terminal.insertText(value); session.terminal.becomeFirstResponder() }
                            .frame(minWidth: 44, minHeight: 44)
                            .accessibilityLabel(punctuationLabel(value))
                            .accessibilityHint("Inserts this character into the terminal.")
                    }
                }
                .disabled(session.state != .connected)
                .buttonStyle(.bordered).font(.system(.caption, design: .monospaced)).padding(8)
            }
            }.background(.bar)
        }
        .navigationTitle(session.device.name).navigationBarTitleDisplayMode(.inline)
        .onChange(of: session.state) { _, state in
            guard state != .connected else { return }
            if session.terminal.controlModifier { session.terminal.controlModifier.toggle() }
            if session.terminal.metaModifier { session.terminal.metaModifier.toggle() }
            controlModifierActive = false
            metaModifierActive = false
        }
        .onReceive(NotificationCenter.default.publisher(for: .terminalViewControlModifierReset, object: session.terminal)) { _ in
            controlModifierActive = false
        }
        .onReceive(NotificationCenter.default.publisher(for: .terminalViewMetaModifierReset, object: session.terminal)) { _ in
            metaModifierActive = false
        }
        .toolbar {
            ToolbarItemGroup(placement: .topBarTrailing) {
                Button("Search", systemImage: "magnifyingglass") {
                    snapshot = String(decoding: session.terminal.getTerminal().getBufferAsData(), as: UTF8.self)
                    searching = true
                }
                if session.state == .connected || session.state == .connecting {
                    Button("Disconnect", systemImage: "stop.circle") { session.disconnect() }
                } else {
                    Button("Reconnect", systemImage: "arrow.clockwise") { session.connect(endpoint: session.endpoint) }
                }
            }
        }
        .sheet(isPresented: $searching) {
            NavigationStack {
                NexusList {
                    ForEach(Array(snapshot.components(separatedBy: .newlines).enumerated()).filter {
                        !search.isEmpty && $0.element.localizedCaseInsensitiveContains(search)
                    }, id: \.offset) { line in
                        Text(line.element).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                    }
                }.searchable(text: $search).navigationTitle("Search terminal snapshot")
                    .toolbar { Button("Done") { searching = false } }
            }
        }
        .alert("Verify SSH host", isPresented: Binding(
            get: { session.challenge != nil && session.challenge?.changed == false }, set: { _ in })) {
                if session.challenge?.changed == false { Button("Trust and connect") { session.acceptHost() } }
                Button("Cancel", role: .cancel) { session.rejectHost() }
            } message: {
                Text("\(session.challenge?.endpoint.authority ?? "")\n\(session.challenge?.fingerprint ?? "")\nCompare this SHA256 fingerprint with the server through a trusted channel before connecting.")
            }
        .sheet(item: Binding(
            get: { session.challenge?.changed == true ? session.challenge : nil },
            set: { if $0 == nil, session.challenge?.changed == true { session.rejectHost() } }
        )) { challenge in
            HostKeyRotationView(session: session, challenge: challenge)
        }
    }
    private func key(_ title: String, bytes: String) -> some View {
        Button(title) { session.send(Data(bytes.utf8)); session.terminal.becomeFirstResponder() }
            .frame(minWidth: 44, minHeight: 44)
            .accessibilityLabel(title == "sudo" ? "Insert sudo prefix" : (title == "ESC" ? "Escape key" : "Tab key"))
            .accessibilityHint(title == "sudo"
                ? "Types sudo followed by a space into the terminal. It does not run the command or grant permissions."
                : "Sends the key to the connected terminal.")
    }
    private func arrow(_ title: String, suffix: String) -> some View {
        Button(title) {
            let prefix = session.terminal.getTerminal().applicationCursor ? "\u{1B}O" : "\u{1B}["
            session.send(Data((prefix + suffix).utf8)); session.terminal.becomeFirstResponder()
        }
        .frame(minWidth: 44, minHeight: 44)
        .accessibilityLabel("\(arrowName(suffix)) arrow key")
        .accessibilityHint("Sends the key to the connected terminal.")
    }

    private func punctuationLabel(_ value: String) -> String {
        switch value {
        case "/": "Insert slash"
        case "|": "Insert vertical bar"
        case "~": "Insert tilde"
        case "-": "Insert hyphen"
        default: "Insert character \(value)"
        }
    }

    private func arrowName(_ suffix: String) -> String {
        switch suffix {
        case "A": "Up"
        case "B": "Down"
        case "C": "Right"
        case "D": "Left"
        default: "Unknown"
        }
    }

}

private struct HostKeyRotationView: View {
    let session: TerminalSession
    let challenge: HostKeyChallenge
    @State private var confirmation = ""
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            NexusForm {
                Section("Server") {
                    LabeledContent("Endpoint", value: challenge.endpoint.authority)
                }
                Section("Previously trusted key") {
                    Text(challenge.previousFingerprint ?? "Unavailable")
                        .font(.caption.monospaced()).textSelection(.enabled)
                }
                Section("New key presented") {
                    Text(challenge.fingerprint)
                        .font(.caption.monospaced()).textSelection(.enabled)
                    Text("A changed key can indicate either a planned rotation or an attack. Verify this new fingerprint directly on the server or through another trusted channel before replacing the saved pin.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
                Section("Confirm out-of-band verification") {
                    TextField("Type the new SHA256 fingerprint", text: $confirmation)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                        .accessibilityIdentifier("hostkey.rotation.confirmation")
                }
            }
            .navigationTitle("Host key changed")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { session.rejectHost(); dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Replace pin", role: .destructive) {
                        session.replaceChangedHostKey(confirmedFingerprint: confirmation.trimmingCharacters(in: .whitespacesAndNewlines))
                        dismiss()
                    }
                    .disabled(confirmation.trimmingCharacters(in: .whitespacesAndNewlines) != challenge.fingerprint)
                }
            }
        }
    }
}

struct TerminalRepresentable: UIViewRepresentable {
    let session: TerminalSession
    let fontSize: Double
    func makeCoordinator() -> Coordinator { Coordinator(session: session) }
    func makeUIView(context: Context) -> SwiftTerm.TerminalView {
        let view = session.terminal
        view.terminalDelegate = context.coordinator
        view.inputAccessoryView = nil
        view.font = .monospacedSystemFont(ofSize: fontSize, weight: .regular)
        return view
    }
    func updateUIView(_ uiView: SwiftTerm.TerminalView, context: Context) {
        if uiView.font.pointSize != fontSize { uiView.font = .monospacedSystemFont(ofSize: fontSize, weight: .regular) }
        uiView.nativeBackgroundColor = .systemBackground
        uiView.nativeForegroundColor = .label
    }
    @MainActor final class Coordinator: NSObject, TerminalViewDelegate {
        let session: TerminalSession
        init(session: TerminalSession) { self.session = session }
        func sizeChanged(source: SwiftTerm.TerminalView, newCols: Int, newRows: Int) { session.resize(columns: newCols, rows: newRows) }
        func send(source: SwiftTerm.TerminalView, data: ArraySlice<UInt8>) { session.send(Data(data)) }
        func setTerminalTitle(source: SwiftTerm.TerminalView, title: String) { session.title = title }
        func hostCurrentDirectoryUpdate(source: SwiftTerm.TerminalView, directory: String?) {}
        func scrolled(source: SwiftTerm.TerminalView, position: Double) {}
        func requestOpenLink(source: SwiftTerm.TerminalView, link: String, params: [String: String]) {}
        func bell(source: SwiftTerm.TerminalView) { UINotificationFeedbackGenerator().notificationOccurred(.warning) }
        // Remote OSC 52 must not overwrite the device clipboard without user interaction.
        func clipboardCopy(source: SwiftTerm.TerminalView, content: Data) {}
        func iTermContent(source: SwiftTerm.TerminalView, content: ArraySlice<UInt8>) {}
        func rangeChanged(source: SwiftTerm.TerminalView, startY: Int, endY: Int) {}
    }
}

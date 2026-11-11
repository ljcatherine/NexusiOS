import SwiftUI
import NexusCore

/// Human-review-only restricted command workflow. No free-form shell command,
/// filesystem path or runtime limit is ever accepted from this screen.
struct PS5NexusCommandReviewView: View {
    @Bindable var ai: AIConnectionsStore
    let connection: AIConnection
    let host: PS5NexusHost
    let workspace: PS5NexusWorkspace
    let endpoint: PS5NexusEndpoint
    var focusReviewID: String? = nil

    @State private var profileID = ""
    @State private var profiles: [PS5NexusCommandProfile] = []
    @State private var submissionID: String?
    @State private var items: [PS5NexusCommandSummary] = []
    @State private var selected: PS5NexusCommandRecord?
    @State private var busy = false
    @State private var loaded = false
    @State private var focusAttempted = false
    @State private var errorMessage: String?
    @State private var decision: PS5NexusCommandDecision?
    @State private var confirmingDecision = false
    @State private var confirmingExecute = false
    @State private var confirmingCancel = false
    @State private var cancelling = false
    @State private var task: Task<Void, Never>?
    @State private var cancelTask: Task<Void, Never>?
    private let client = PS5NexusCommandClient()

    private var pendingKey: String {
        "Nexus.command.pending.\(connection.id.uuidString.lowercased()).\(host.rawValue).\(workspace.id)"
    }

    var body: some View {
        NexusForm {
            Section("Restricted host commands") {
                Label("\(host.title) · \(workspace.name)", systemImage: "checkmark.shield")
                Text("Commands use fixed administrator profiles and immutable captured inputs. Nexus cannot run arbitrary shell instructions. Each execution requires an independent workspace execute grant and your explicit review.")
                    .font(.footnote).foregroundStyle(.secondary)
            }
            if let errorMessage {
                Section {
                    Label(errorMessage, systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.red)
                    Button("Reload saved reviews", systemImage: "arrow.clockwise") { reload() }.disabled(busy)
                }
            }
            if busy { Section { ProgressView("Checking the gateway…") } }
            if let selected {
                Section("Captured fixed profile") {
                    Button("Back to command reviews", systemImage: "chevron.left") {
                        self.selected = nil
                        reload()
                    }.disabled(busy)
                    LabeledContent("Profile", value: selected.proposal.profileID)
                    LabeledContent("Requested by", value: selected.origin == "agent" ? "NexusAI task" : "You")
                    LabeledContent("Status", value: selected.status.capitalized)
                    LabeledContent("Expires") { Text(Date(timeIntervalSince1970: selected.expiresAt), style: .relative) }
                    Text("Review SHA-256: \(selected.digest)")
                        .font(.caption.monospaced()).textSelection(.enabled)
                    Text("Snapshot ID: \(selected.proposal.snapshotID)")
                        .font(.caption.monospaced()).textSelection(.enabled)
                }
                Section("Exact approved invocation") {
                    Text(selected.proposal.invocation.executable).font(.caption.monospaced()).textSelection(.enabled)
                    ForEach(Array(selected.proposal.invocation.arguments.enumerated()), id: \.offset) { index, argument in
                        LabeledContent("Argument \(index + 1)") { Text(argument).font(.caption.monospaced()).textSelection(.enabled) }
                    }
                    LabeledContent("Timeout", value: "\(selected.proposal.invocation.limits.timeoutMS) ms")
                    LabeledContent("Memory cap", value: ByteCountFormatter.string(fromByteCount: Int64(selected.proposal.invocation.limits.memoryBytes), countStyle: .memory))
                    LabeledContent("Processes", value: "\(selected.proposal.invocation.limits.processes)")
                    LabeledContent("Input files", value: "\(selected.proposal.inputs.count)")
                }
                if !selected.proposal.inputs.isEmpty {
                    Section("Captured input manifest") {
                        ForEach(selected.proposal.inputs, id: \.path) { input in
                            VStack(alignment: .leading, spacing: 4) {
                                Text(input.path).font(.caption.monospaced())
                                Text("\(input.sizeBytes) bytes · SHA-256 \(input.sha256)")
                                    .font(.caption2.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
                            }
                        }
                        Text("Input contents were captured by the host at proposal time. Editing the live file cannot change these approved bytes.")
                            .font(.footnote).foregroundStyle(.secondary)
                    }
                }
                if let execution = selected.execution {
                    Section("Durable host receipt") {
                        Label(execution.phase.capitalized, systemImage: execution.phase == "completed" ? "checkmark.seal" : "clock.arrow.circlepath")
                        Text("Operation \(execution.operationID)").font(.caption.monospaced()).textSelection(.enabled)
                        if execution.cancelRequested == true {
                            Label("Cancellation requested; completion still requires the original signed host receipt.", systemImage: "hand.raised")
                                .font(.footnote).foregroundStyle(.orange)
                        }
                        if let receipt = execution.receipt {
                            LabeledContent("Outcome", value: receipt.status)
                            if let result = receipt.result {
                                LabeledContent("Exit code", value: "\(result.exitCode)")
                                if result.timedOut || result.cancelled || result.truncated {
                                    Text("Timed out: \(result.timedOut.description) · Cancelled: \(result.cancelled.description) · Truncated: \(result.truncated.description)")
                                        .font(.caption).foregroundStyle(.secondary)
                                }
                                if !result.stdout.isEmpty {
                                    DisclosureGroup("Standard output") { Text(result.stdout).font(.caption.monospaced()).textSelection(.enabled) }
                                }
                                if !result.stderr.isEmpty {
                                    DisclosureGroup("Standard error") { Text(result.stderr).font(.caption.monospaced()).textSelection(.enabled) }
                                }
                            }
                        } else {
                            Text("An interrupted request cannot be assumed successful or replayed. Check the saved host receipt before any new work.")
                                .font(.footnote).foregroundStyle(.secondary)
                        }
                    }
                }
                if selected.canReview {
                    Section("Human decision") {
                        Button("Approve this exact profile and snapshot", systemImage: "checkmark.shield") {
                            decision = .approve; confirmingDecision = true
                        }.disabled(busy)
                        Button("Reject command", systemImage: "xmark.shield", role: .destructive) {
                            decision = .reject; confirmingDecision = true
                        }.disabled(busy)
                        Text("Approval records your decision only; it never automatically executes code.")
                            .font(.footnote).foregroundStyle(.secondary)
                    }
                }
                if selected.canExecute {
                    Section("One-time restricted execution") {
                        Button("Execute approved fixed profile", systemImage: "play.shield") {
                            confirmingExecute = true
                        }.disabled(busy)
                        Text("The host rechecks current owner permissions and the exact captured inputs. Repeated or uncertain deliveries use one durable operation, not a new execution.")
                            .font(.footnote).foregroundStyle(.secondary)
                    }
                }
                if selected.canReconcile {
                    Section("Interrupted operation") {
                        Button("Check original host receipt", systemImage: "arrow.clockwise.shield") {
                            execute(.reconcile)
                        }.disabled(busy)
                    }
                }
                if selected.canCancel {
                    Section("Cancel this exact command") {
                        Button(selected.status == "executing" || busy
                               ? "Request cancellation of in-flight command" : "Withdraw this command",
                               systemImage: "stop.circle", role: .destructive) {
                            confirmingCancel = true
                        }.disabled(cancelling)
                        Text("Before execution, withdrawal irreversibly rejects the review. In flight, the host stops only the original signed operation; the result stays uncertain until its receipt is verified.")
                            .font(.footnote).foregroundStyle(.secondary)
                    }
                }
            } else {
                Section("Request a fixed-profile review") {
                    if profiles.isEmpty {
                        Label("No command profiles are available for this workspace and account.", systemImage: "lock.shield")
                            .font(.footnote).foregroundStyle(.secondary)
                    } else {
                        Picker("Administrator profile", selection: $profileID) {
                            Text("Select a fixed profile").tag("")
                            ForEach(profiles) { profile in
                                Text(profile.id).tag(profile.id)
                            }
                        }
                        .disabled(busy || submissionID != nil)
                    }
                    if let submissionID {
                        Text("Saved submission: \(submissionID)").font(.caption.monospaced()).textSelection(.enabled)
                        Text("A previous submission may have succeeded even if the response was lost. Reload the review list before attempting anything new.")
                            .font(.footnote).foregroundStyle(.secondary)
                    }
                    Button(submissionID == nil ? "Capture for human review" : "Retry the same captured request", systemImage: "doc.badge.clock") {
                        submit()
                    }.disabled(busy || profileID.isEmpty || !profiles.contains(where: { $0.id == profileID }))
                    Text("The profile must be allowlisted by the Debian or NixOS administrator. Command arguments cannot be edited here.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
                Section("Saved command reviews") {
                    if loaded && items.isEmpty {
                        ContentUnavailableView("No restricted command reviews", systemImage: "checkmark.shield",
                            description: Text("Use an administrator-defined profile to request a captured, human-reviewed command."))
                    }
                    ForEach(items) { item in
                        Button { open(item.id) } label: {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(item.profileID).font(.body.monospaced())
                                Text((item.executionPhase ?? item.status).capitalized).font(.caption).foregroundStyle(.secondary)
                            }
                        }.disabled(busy)
                    }
                }
            }
        }
        .navigationTitle("Command review")
        .toolbar { Button("Refresh", systemImage: "arrow.clockwise") { reload() }.disabled(busy) }
        .confirmationDialog("Review this captured command?", isPresented: $confirmingDecision, titleVisibility: .visible) {
            Button(decision == .approve ? "Approve exact snapshot" : "Reject command", role: decision == .reject ? .destructive : nil) { decide() }
            Button("Cancel", role: .cancel) { decision = nil }
        } message: { Text("Your decision is bound to the immutable profile and input digest shown. Approval does not run code.") }
        .confirmationDialog("Execute this restricted profile?", isPresented: $confirmingExecute, titleVisibility: .visible) {
            Button("Execute once", role: .destructive) { execute(.execute) }
            Button("Cancel", role: .cancel) {}
        } message: { Text("This may run actual isolated code on the selected host. The gateway checks a separate execute grant, and the saved receipt must be reconciled after an uncertain response.") }
        .confirmationDialog("Cancel this specific restricted command?", isPresented: $confirmingCancel, titleVisibility: .visible) {
            Button("Withdraw or stop exact operation", role: .destructive) { cancelCommand() }
            Button("Keep command", role: .cancel) {}
        } message: { Text("This cannot be undone. An in-flight cancellation request is not proof of termination; inspect the signed host receipt afterward.") }
        .onAppear {
            if !loaded { reload() }
        }
        .onDisappear { task?.cancel(); cancelTask?.cancel() }
    }

    private func submit() {
        run { token in
            // The existing Keychain-backed credential identity prevents a
            // saved request from one signed-in owner from silently becoming
            // a new command request after sign-out/token rotation.
            let identity = try ai.patchRequestIdentity(for: connection, token: token)
                .uuidString.lowercased()
            restorePending(identity: identity)
            let id = submissionID ?? UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
            // Non-secret retry identity is recorded *before* transmission,
            // alongside a credential-scoped Keychain identity (not the token).
            UserDefaults.standard.set(["id": id, "profile": profileID, "identity": identity], forKey: pendingKey)
            submissionID = id
            let item = try await client.propose(profileID: profileID, submissionID: id, endpoint: endpoint,
                                                token: token, host: host, workspaceID: workspace.id)
            try Task.checkCancellation()
            UserDefaults.standard.removeObject(forKey: pendingKey)
            submissionID = nil
            selected = item
        }
    }
    private func reload() {
        run { token in
            let identity = try ai.patchRequestIdentity(for: connection, token: token)
                .uuidString.lowercased()
            restorePending(identity: identity)
            profiles = try await client.profiles(endpoint: endpoint, token: token, host: host,
                workspaceID: workspace.id, generation: workspace.generation)
            if submissionID == nil && !profiles.contains(where: { $0.id == profileID }) { profileID = "" }
            items = try await client.list(endpoint: endpoint, token: token, host: host, workspaceID: workspace.id)
            loaded = true
            // A task checkpoint deep-links to its original review only once.
            // Reopening the list must still work, and the server independently
            // checks owner, root and original checkpoint on every decision.
            if let focusReviewID, !focusAttempted {
                focusAttempted = true
                guard focusReviewID.range(of: "^[0-9a-f]{32}$", options: .regularExpression) ==
                        focusReviewID.startIndex..<focusReviewID.endIndex else { return }
                selected = try await client.detail(endpoint: endpoint, token: token, host: host,
                                                   workspaceID: workspace.id, id: focusReviewID)
            }
        }
    }

    private func restorePending(identity: String) {
        guard let saved = UserDefaults.standard.dictionary(forKey: pendingKey) else { return }
        guard saved["identity"] as? String == identity,
              let id = saved["id"] as? String,
              id.range(of: "^[0-9a-f]{32}$", options: .regularExpression) == id.startIndex..<id.endIndex,
              let profile = saved["profile"] as? String,
              profile.range(of: "^[a-z][a-z0-9_-]{0,31}$", options: .regularExpression) == profile.startIndex..<profile.endIndex else {
            // Credential rotation invalidates *only* this non-secret retry
            // marker; it does not delete the actual host review or Keychain.
            UserDefaults.standard.removeObject(forKey: pendingKey)
            submissionID = nil
            return
        }
        submissionID = id
        profileID = profile
    }
    private func open(_ id: String) {
        run { token in
            selected = try await client.detail(endpoint: endpoint, token: token, host: host, workspaceID: workspace.id, id: id)
        }
    }
    private func decide() {
        guard let selected, let decision else { return }
        self.decision = nil
        run { token in
            self.selected = try await client.decide(decision, record: selected, endpoint: endpoint,
                                                     token: token, host: host, workspaceID: workspace.id)
        }
    }
    private func execute(_ action: PS5NexusCommandAction) {
        guard let selected else { return }
        run { token in
            self.selected = try await client.action(action, record: selected, endpoint: endpoint,
                                                     token: token, host: host, workspaceID: workspace.id)
        }
    }
    private func cancelCommand() {
        guard let captured = selected, !cancelling, captured.canCancel else { return }
        // A separate task lets the user stop an operation while the original
        // execute POST is still awaiting the host's bounded output. Cancelling
        // this HTTP request never means the host stopped; retry/reconcile use
        // the saved operation identity.
        cancelling = true
        cancelTask = Task { @MainActor in
            defer { cancelling = false }
            do {
                let token = try await ai.ps5NexusToken(for: connection, reuseConnectionCredential: true)
                let updated = try await client.action(.cancel, record: captured, endpoint: endpoint,
                                                      token: token, host: host, workspaceID: workspace.id)
                if selected?.id == captured.id { selected = updated }
            } catch is CancellationError {
            } catch let failure as PS5NexusError {
                errorMessage = failure.localizedDescription
            } catch {
                errorMessage = "Cancellation outcome is unknown. Refresh this review, then check its original receipt; never start a second command automatically."
            }
        }
    }
    private func run(_ operation: @escaping @MainActor (String) async throws -> Void) {
        guard !busy else { return }
        busy = true
        errorMessage = nil
        task = Task { @MainActor in
            defer { busy = false }
            do {
                let token = try await ai.ps5NexusToken(for: connection, reuseConnectionCredential: true)
                try Task.checkCancellation()
                try await operation(token)
            } catch is CancellationError {
                // Cancelling the view never authorizes replay or stops running host code.
            } catch let failure as PS5NexusError {
                self.errorMessage = failure.localizedDescription
            } catch {
                self.errorMessage = "The gateway could not confirm the command's state. Reload saved reviews and check the original host receipt before any new action."
            }
        }
    }
}

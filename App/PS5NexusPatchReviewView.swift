import SwiftUI
import NexusCore

/// Only the signed-in user's gateway credential reaches this view. The gateway
/// selects the private review credential after checking current workspace grants.
struct PS5NexusPatchReviewView: View {
    @Bindable var ai: AIConnectionsStore
    let connection: AIConnection
    let host: PS5NexusHost
    let workspace: PS5NexusWorkspace
    let endpoint: PS5NexusEndpoint

    @State private var items: [PS5NexusPatchSummary] = []
    @State private var selected: PS5NexusPatchRecord?
    @State private var decision: PS5NexusPatchDecision?
    @State private var confirming = false
    @State private var confirmingApply = false
    @State private var busy = false
    @State private var loaded = false
    @State private var error: String?
    @State private var task: Task<Void, Never>?
    @State private var relativePath = ""
    @State private var replacement = ""
    @State private var pending: PS5NexusPatchDraft?
    @State private var draftLoaded = false
    private let client = PS5NexusPatchClient()

    var body: some View {
        NexusForm {
            Section {
                Label("\(host.title) · \(workspace.name)", systemImage: "folder.badge.person.crop")
                Text(workspace.readOnly == false
                     ? "Managed workspace. Approving an eligible proposal authorizes its exact replacement after the gateway checks execution permissions. Review the captured original and replacement carefully."
                     : "Review only. Approving records your decision; it does not change workspace files. Proposals contain captured source text and expire if not reviewed in time.")
                    .font(.footnote).foregroundStyle(.secondary)
            }
            if let error {
                Section {
                    Label(error, systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.red)
                    Button("Reload proposals") { reload() }.disabled(busy)
                }
            }
            if busy { Section { ProgressView("Contacting gateway…") } }
            if let selected {
                Section("Proposal") {
                    Button("Back to proposals", systemImage: "chevron.left") {
                        self.selected = nil
                        reload()
                    }.disabled(busy)
                    Text(selected.proposal.path).font(.body.monospaced()).textSelection(.enabled)
                    LabeledContent("Status", value: selected.status.capitalized)
                    LabeledContent("Expires") {
                        Text(Date(timeIntervalSince1970: selected.expiresAt), style: .relative)
                    }
                    Text("Snapshot SHA-256: \(selected.digest)")
                        .font(.caption.monospaced()).textSelection(.enabled)
                }
                if let execution = selected.execution {
                    Section("Execution receipt") {
                        Label(execution.phase.capitalized, systemImage: execution.phase == "applied" ? "checkmark.seal" : "clock.arrow.circlepath")
                        Text("Operation \(execution.operationID)").font(.caption.monospaced()).textSelection(.enabled)
                        if execution.phase == "uncertain" || execution.phase == "dispatching" {
                            Text("The outcome must be verified from the saved host receipt. The gateway will not blindly repeat this write.")
                                .font(.footnote).foregroundStyle(.secondary)
                        }
                    }
                }
                Section("Original file") { source(selected.proposal.original) }
                Section("Proposed replacement") { source(selected.proposal.replacement) }
                if selected.canApply {
                    Section("Apply reviewed edit") {
                        Button("Apply approved replacement", systemImage: "doc.badge.arrow.up") {
                            confirmingApply = true
                        }.disabled(busy)
                        Text("This replaces the existing file with the approved text. The host checks the original file and workspace identity again; changed files are refused.")
                            .font(.footnote).foregroundStyle(.secondary)
                    }
                }
                if selected.canReconcile {
                    Section("Recover execution status") {
                        Button("Check saved host receipt", systemImage: "arrow.clockwise.shield") {
                            submitExecution(.reconcile)
                        }.disabled(busy)
                        Text("Checks the original operation. This never submits the replacement again.")
                            .font(.footnote).foregroundStyle(.secondary)
                    }
                }
                if selected.status == "pending" {
                    Section("Your decision") {
                        Button("Approve this exact proposal", systemImage: "checkmark.shield") {
                            decision = .approve
                            confirming = true
                        }.disabled(busy || !selected.canReview)
                        Button("Reject proposal", systemImage: "xmark.shield", role: .destructive) {
                            decision = .reject
                            confirming = true
                        }.disabled(busy || !selected.canReview)
                        if !selected.canReview {
                            Text("This proposal has expired. A new proposal is required.")
                                .font(.footnote).foregroundStyle(.secondary)
                        }
                    }
                }
            } else {
                composer
                Section("Proposals") {
                    if loaded && items.isEmpty {
                        ContentUnavailableView("No patch proposals", systemImage: "doc.text.magnifyingglass",
                            description: Text("Submit a proposal, review its captured contents, then apply an eligible approved manual edit."))
                    }
                    ForEach(items) { item in
                        Button { open(item) } label: {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(item.path).font(.body.monospaced()).lineLimit(3)
                                Text((item.executionPhase ?? item.status).capitalized).font(.caption).foregroundStyle(.secondary)
                            }
                        }.disabled(busy)
                    }
                }
            }
        }
        .navigationTitle("Patch review")
        .toolbar { Button("Refresh", systemImage: "arrow.clockwise") { reload() }.disabled(busy) }
        .confirmationDialog(decision == .approve ? "Approve this captured replacement?" : "Reject this proposal?",
                            isPresented: $confirming, titleVisibility: .visible) {
            Button(decision == .approve ? "Approve proposal" : "Reject proposal",
                   role: decision == .reject ? .destructive : nil) { submitDecision() }
            Button("Cancel", role: .cancel) { decision = nil }
        } message: {
            Text(selected?.manualExecutionAllowed == true
                 ? "Your approval records this exact replacement. Use Apply approved replacement afterward to start the edit. Current write permission is still required."
                 : selected?.proposal.workspaceGeneration != nil
                    ? "Approval authorizes replacing this file with the exact text shown in this managed workspace. Execution still requires current write permission."
                    : "Your decision is bound to the exact source and replacement shown. This legacy proposal is review-only.")
        }
        .confirmationDialog("Apply this approved replacement?", isPresented: $confirmingApply,
                            titleVisibility: .visible) {
            Button("Apply replacement", role: .destructive) { submitExecution(.apply) }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("The host will replace this file only if its original contents and managed workspace identity still match. If interrupted, reload and check the saved receipt.")
        }
        .onAppear { if !loaded { reload() } }
        .onDisappear { task?.cancel() }
    }

    private func source(_ text: String) -> some View {
        ScrollView(.horizontal) {
            Text(text.isEmpty ? "(Empty file)" : text)
                .font(.caption.monospaced()).textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private var composer: some View {
        Section("Propose a replacement") {
            TextField("Relative file path", text: $relativePath)
                .textInputAutocapitalization(.never).autocorrectionDisabled()
                .disabled(busy || !draftLoaded || pending != nil)
            TextEditor(text: $replacement)
                .font(.body.monospaced()).frame(minHeight: 160)
                .accessibilityLabel("Replacement file contents")
                .textInputAutocapitalization(.never).autocorrectionDisabled()
                .disabled(busy || !draftLoaded || pending != nil)
            Text("Replace the entire existing file with this text (up to 64 KiB). Empty text proposes an empty file. Submission captures the original for review; it does not approve or apply the edit.")
                .font(.footnote).foregroundStyle(.secondary)
            if let pending {
                Text("Saved request: \(pending.submissionID)").font(.caption.monospaced())
                Text("Contents are frozen. If a request times out, retry sends the exact saved request, including after reopening Nexus.")
                    .font(.footnote).foregroundStyle(.secondary)
            }
            Button(pending == nil ? "Submit proposal for review" : "Retry saved proposal",
                   systemImage: "paperplane") { submitProposal() }
                .disabled(busy || !draftLoaded || (pending == nil && relativePath.isEmpty))
        }
    }

    private func binding(token: String) throws -> PS5NexusPatchBinding {
        PS5NexusPatchBinding(connectionID: connection.id, endpoint: endpoint,
            identity: try ai.patchRequestIdentity(for: connection, token: token),
            host: host, workspaceID: workspace.id)
    }

    private func restoreDraft(token: String) throws {
        draftLoaded = false
        let saved = try ai.patchDraftStore().load(binding: binding(token: token))
        pending = saved
        if let saved {
            relativePath = saved.path
            replacement = saved.replacement
        }
        draftLoaded = true
    }

    private func submitProposal() {
        run { token in
            draftLoaded = false
            let scope = try binding(token: token)
            let store = try ai.patchDraftStore()
            // Re-read before preparing, so another view cannot replace a pending request.
            let draft: PS5NexusPatchDraft
            let saved = try store.load(binding: scope)
            if let pending {
                guard pending.binding == scope, saved == pending else {
                    throw PS5NexusPatchDraftError.invalid
                }
                draft = pending
            } else if let saved {
                draft = saved
            } else {
                do {
                    draft = try store.prepare(binding: scope, path: relativePath, replacement: replacement)
                } catch {
                    // Invalid input can be corrected immediately. A partial storage
                    // failure instead recovers the frozen request or keeps editing locked.
                    try? restoreDraft(token: token)
                    throw error
                }
            }
            pending = draft
            draftLoaded = true
            relativePath = draft.path
            replacement = draft.replacement
            try Task.checkCancellation()
            let result = try await client.propose(draft, binding: scope, endpoint: endpoint, token: token)
            try Task.checkCancellation()
            // A changed session must not consume or expose a previous session's result.
            guard try binding(token: token) == scope else { throw PS5NexusPatchDraftError.identityChanged }
            try store.complete(draft, response: result)
            pending = nil
            relativePath = ""
            replacement = ""
            selected = result
        }
    }

    private func reload() {
        selected = nil
        run { token in
            try restoreDraft(token: token)
            let result = try await client.list(endpoint: endpoint, token: token, host: host, workspaceID: workspace.id)
            try Task.checkCancellation()
            items = result
            loaded = true
        }
    }
    private func open(_ item: PS5NexusPatchSummary) {
        run { token in
            let result = try await client.detail(endpoint: endpoint, token: token, host: host,
                                                 workspaceID: workspace.id, id: item.id)
            try Task.checkCancellation()
            selected = result
        }
    }
    private func submitDecision() {
        guard let record = selected, let decision else { return }
        self.decision = nil
        run { token in
            let result = try await client.decide(decision, record: record, endpoint: endpoint,
                token: token, host: host, workspaceID: workspace.id)
            try Task.checkCancellation()
            selected = result
        }
    }
    private func submitExecution(_ action: PS5NexusPatchExecutionAction) {
        guard let record = selected else { return }
        run { token in
            let result = try await client.execute(action, record: record, endpoint: endpoint,
                token: token, host: host, workspaceID: workspace.id)
            try Task.checkCancellation()
            selected = result
        }
    }
    private func run(_ action: @escaping @MainActor (String) async throws -> Void) {
        guard !busy else { return }
        busy = true
        error = nil
        task = Task { @MainActor in
            defer { busy = false }
            do {
                let token = try await ai.ps5NexusToken(for: connection, reuseConnectionCredential: true)
                try Task.checkCancellation()
                try await action(token)
            } catch is CancellationError {
                // Navigation away cancels only this short request, never a file operation.
            } catch let failure as PS5NexusError {
                self.error = failure.localizedDescription
            } catch let failure as PS5NexusPatchDraftError {
                self.error = failure.localizedDescription
            } catch {
                self.error = "The request could not finish. Reload to recover the saved proposal or execution receipt before trying again. An interrupted write must be checked using its original receipt."
            }
        }
    }
}

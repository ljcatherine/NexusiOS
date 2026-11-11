import Foundation

struct PS5NexusPatchEnvelope: Decodable {
    let host: String
    let workspaceID: String
    let executionEnabled: Bool
    let patch: PS5NexusPatchRecord?
    let patches: [PS5NexusPatchSummary]?
    enum CodingKeys: String, CodingKey {
        case host, patch, patches
        case workspaceID = "workspace_id", executionEnabled = "execution_enabled"
    }
}

public enum PS5NexusPatchDecision: String, Sendable { case approve, reject }
public enum PS5NexusPatchExecutionAction: String, Sendable { case apply, reconcile }

public struct PS5NexusPatchClient: Sendable {
    public init() {}
    private let http = PS5NexusHTTPClient()
    /// Strict route recognition keeps larger transport limits confined to patch records.
    static func isPatchRoute(_ path: String) -> Bool {
        path.range(of: "^/nexus/workspaces/(debian|nixos)/[a-z][a-z0-9_-]{0,31}/patches(/[0-9a-f]{32}(/(decision|apply|reconcile))?)?$",
                   options: .regularExpression) == path.startIndex..<path.endIndex
    }
    private func path(host: PS5NexusHost, workspaceID: String) throws -> String {
        guard PS5NexusPatchValidation.validScope(host: host.rawValue, workspaceID: workspaceID) else { throw PS5NexusError.invalidResponse }
        return "/nexus/workspaces/\(host.rawValue)/\(workspaceID)/patches"
    }
    public func propose(_ draft: PS5NexusPatchDraft, binding: PS5NexusPatchBinding,
                        endpoint: PS5NexusEndpoint, token: String) async throws -> PS5NexusPatchRecord {
        try draft.validate()
        guard draft.binding == binding, binding.endpoint == endpoint.baseURL.absoluteString else {
            throw PS5NexusPatchDraftError.identityChanged
        }
        let route = try path(host: binding.host, workspaceID: binding.workspaceID)
        let result: PS5NexusPatchEnvelope = try await http.send(endpoint: endpoint, path: route,
            method: "POST", token: token, body: draft.body)
        return try Self.validatedProposal(result, draft: draft)
    }
    static func validatedProposal(_ result: PS5NexusPatchEnvelope,
                                  draft: PS5NexusPatchDraft) throws -> PS5NexusPatchRecord {
        let binding = draft.binding
        guard result.host == binding.host.rawValue, result.workspaceID == binding.workspaceID,
              !result.executionEnabled, let record = result.patch else { throw PS5NexusError.invalidResponse }
        try draft.validateResponse(record)
        return record
    }
    public func list(endpoint: PS5NexusEndpoint, token: String, host: PS5NexusHost,
                     workspaceID: String) async throws -> [PS5NexusPatchSummary] {
        let route = try path(host: host, workspaceID: workspaceID)
        let result: PS5NexusPatchEnvelope = try await http.send(endpoint: endpoint, path: route, token: token)
        guard result.host == host.rawValue, result.workspaceID == workspaceID, !result.executionEnabled,
              let items = result.patches, items.count <= 100, items.allSatisfy(\.valid),
              Set(items.map(\.id)).count == items.count else { throw PS5NexusError.invalidResponse }
        return items
    }
    public func detail(endpoint: PS5NexusEndpoint, token: String, host: PS5NexusHost,
                       workspaceID: String, id: String) async throws -> PS5NexusPatchRecord {
        guard PS5NexusPatchValidation.hex(id, count: 32) else { throw PS5NexusError.invalidResponse }
        let route = try path(host: host, workspaceID: workspaceID) + "/\(id)"
        let result: PS5NexusPatchEnvelope = try await http.send(endpoint: endpoint, path: route, token: token)
        return try validated(result, host: host, workspaceID: workspaceID, id: id)
    }
    public func decide(_ decision: PS5NexusPatchDecision, record: PS5NexusPatchRecord,
                       endpoint: PS5NexusEndpoint, token: String, host: PS5NexusHost,
                       workspaceID: String) async throws -> PS5NexusPatchRecord {
        guard record.valid(host: host, workspaceID: workspaceID), record.canReview else {
            throw PS5NexusError.patchReviewConflict
        }
        let route = try path(host: host, workspaceID: workspaceID) + "/\(record.id)/decision"
        let body = try JSONEncoder().encode(["digest": record.digest, "decision": decision.rawValue])
        let result: PS5NexusPatchEnvelope = try await http.send(endpoint: endpoint, path: route,
            method: "POST", token: token, body: body)
        let updated = try validated(result, host: host, workspaceID: workspaceID, id: record.id)
        guard updated.digest == record.digest, updated.proposal == record.proposal,
              updated.status == (decision == .approve ? "approved" : "rejected") else {
            throw PS5NexusError.invalidResponse
        }
        return updated
    }
    private func validated(_ result: PS5NexusPatchEnvelope, host: PS5NexusHost,
                           workspaceID: String, id: String, execution: Bool = false) throws -> PS5NexusPatchRecord {
        guard result.host == host.rawValue, result.workspaceID == workspaceID, result.executionEnabled == execution,
              let item = result.patch, item.id == id, item.valid(host: host, workspaceID: workspaceID) else {
            throw PS5NexusError.invalidResponse
        }
        return item
    }

    public func execute(_ action: PS5NexusPatchExecutionAction, record: PS5NexusPatchRecord,
                        endpoint: PS5NexusEndpoint, token: String, host: PS5NexusHost,
                        workspaceID: String) async throws -> PS5NexusPatchRecord {
        guard record.valid(host: host, workspaceID: workspaceID),
              action == .apply ? record.canApply : record.canReconcile else {
            throw PS5NexusError.patchReviewConflict
        }
        let route = try path(host: host, workspaceID: workspaceID) + "/\(record.id)/\(action.rawValue)"
        let body = try JSONEncoder().encode(["digest": record.digest])
        let response: PS5NexusPatchEnvelope = try await http.send(endpoint: endpoint, path: route,
            method: "POST", token: token, body: body)
        let updated = try validated(response, host: host, workspaceID: workspaceID, id: record.id, execution: true)
        guard updated.digest == record.digest, updated.proposal == record.proposal,
              updated.manualExecutionAllowed == true, updated.status == "executing",
              let execution = updated.execution,
              record.execution.map({ $0.operationID == execution.operationID }) ?? true else {
            throw PS5NexusError.invalidResponse
        }
        return updated
    }
}

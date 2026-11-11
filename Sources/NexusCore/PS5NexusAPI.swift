import Foundation
import Crypto
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

private let ps5NexusMessageByteLimit = 48 * 1_024
private let ps5NexusFinishReasons = ["stop", "length", "content_filter", "tool_calls", "function_call"]

/// A separate, opt-in management endpoint. Never derived from a PS5 address or
/// discovered on the LAN. Chat and model discovery continue to use AIAPIClient.
public struct PS5NexusEndpoint: Equatable, Sendable {
    public let baseURL: URL

    public init(managementURL: String, connection: AIConnection, reuseConnectionCredential: Bool = false) throws {
        guard connection.enabled, !connection.provider.isOnDevice,
              connection.provider == .ps5lmPlus || connection.provider == .customOpenAICompatible,
              !managementURL.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              managementURL.utf8.count <= 2_048,
              let parts = URLComponents(string: managementURL.trimmingCharacters(in: .whitespacesAndNewlines)),
              let scheme = parts.scheme?.lowercased(),
              let host = parts.host?.lowercased(),
              !host.isEmpty,
              parts.user == nil, parts.password == nil,
              parts.query == nil, parts.fragment == nil,
              let url = parts.url
        else { throw PS5NexusError.invalidEndpoint }

        // An inference API key/OIDC token may ONLY be reused with the identical
        // origin. A separately configured controller on :8082 needs a dedicated
        // management bearer token in Keychain.
        let chatURL = try connection.validatedBaseURL()
        guard let chatParts = URLComponents(url: chatURL, resolvingAgainstBaseURL: false),
              (!reuseConnectionCredential ||
                (scheme == chatParts.scheme?.lowercased() &&
                 host == chatParts.host?.lowercased() &&
                 Self.port(for: parts) == Self.port(for: chatParts))),
              parts.path == "/v1" || parts.path.hasSuffix("/v1"),
              !parts.path.contains("//"),
              !parts.path.split(separator: "/").contains(where: { $0 == ".." || $0 == "." }),
              scheme == "https" || (scheme == "http" && Self.isLiteralPrivateAddress(host))
        else { throw PS5NexusError.invalidEndpoint }
        baseURL = url
    }

    private static func port(for components: URLComponents) -> Int {
        components.port ?? (components.scheme?.lowercased() == "https" ? 443 : 80)
    }

    /// HTTP is accepted only on literal private/loopback IPv4 addresses. No
    /// DNS names: resolution could send credentials to a public endpoint.
    static func isLiteralPrivateAddress(_ host: String) -> Bool {
        let pieces = host.split(separator: ".", omittingEmptySubsequences: false)
        guard pieces.count == 4, pieces.allSatisfy({ !$0.isEmpty &&
            $0.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }) && $0.count <= 3 }) else { return false }
        let octets = pieces.compactMap { UInt8($0) }
        guard octets.count == 4 else { return false }
        return octets[0] == 10 || octets[0] == 127 ||
            (octets[0] == 192 && octets[1] == 168) ||
            (octets[0] == 172 && (16...31).contains(octets[1])) ||
            (octets[0] == 100 && (64...127).contains(octets[1]))
    }

    func url(path: String, query: [URLQueryItem] = []) throws -> URL {
        guard path.hasPrefix("/"), !path.contains("//"), !path.contains("?"),
              !path.contains("#"), !path.split(separator: "/").contains(where: { $0 == ".." || $0 == "." }),
              var parts = URLComponents(url: baseURL, resolvingAgainstBaseURL: false) else {
            throw PS5NexusError.invalidEndpoint
        }
        let prefix = parts.path.hasSuffix("/") ? String(parts.path.dropLast()) : parts.path
        parts.path = prefix + path
        parts.queryItems = query.isEmpty ? nil : query
        guard let url = parts.url else { throw PS5NexusError.invalidEndpoint }
        return url
    }
}

public enum PS5NexusError: LocalizedError, Equatable, Sendable {
    case invalidEndpoint
    case noCredential
    case unauthorized
    case forbidden
    case unavailable
    case invalidResponse
    case requestTooLarge
    case responseTooLarge
    case cancelled
    case runFailed
    case runNotFound
    case runExpired
    case patchNotFound
    case patchReviewConflict
    case failed(Int)

    public static func taskFailureDescription(phase: String?) -> String {
        switch phase {
        case "context limit exceeded": "This task exceeds the model's available context. Reduce the selected workspace text or conversation history, then retry."
        case "upstream unavailable": "The model or workspace service is unavailable. Check its connection and retry."
        case "subagent cancellation raced completion": "A subagent was cancelled as it finished. Retry the task to get a consistent result."
        case "authorization revoked": "Access to this task or workspace was revoked. Check the gateway permissions."
        case "authorization unavailable": "Nexus could not verify task access with the gateway. Check the gateway and retry."
        case "inference state unknown": "The PS5's previous inference state is unknown. Verify it is idle before clearing the gateway safety guard."
        default: PS5NexusError.runFailed.localizedDescription
        }
    }

    public var errorDescription: String? {
        switch self {
        case .invalidEndpoint: "Enter an explicit management URL ending in /v1. HTTP is allowed only for a literal private IPv4 address; existing AI credentials require an identical HTTPS origin."
        case .noCredential: "PS5 management requires a dedicated Keychain bearer token or an eligible signed-in gateway session."
        case .unauthorized: "The PS5 management credential was rejected. Check the selected AI connection's authentication."
        case .forbidden: "This account does not have permission for that action. Check the gateway access settings."
        case .unavailable: "PS5 management is unavailable. Check that the optional bridge is running and enabled."
        case .invalidResponse: "The management API returned an unexpected response."
        case .requestTooLarge: "The management request exceeds the permitted size."
        case .responseTooLarge: "The management reply exceeds the permitted size."
        case .cancelled: "The orchestrated task was cancelled at a safe inference boundary."
        case .runFailed: "The orchestrated task failed. You can review the prompt and try again."
        case .runNotFound: "The saved task was not found on the orchestrator."
        case .patchNotFound: "This patch proposal was not found in the selected workspace."
        case .patchReviewConflict: "This proposal expired or has already been reviewed. Reload it before continuing."
        case .runExpired: "The saved task result is no longer available. Check task history before starting it again."
        case .failed(let code): "PS5 management request failed (HTTP \(code))."
        }
    }
}

public struct PS5NexusHTTPClient: Sendable {
    public init() {}

    public func models(endpoint: PS5NexusEndpoint, token: String) async throws -> [PS5NexusModel] {
        let list: PS5NexusModelList = try await send(endpoint: endpoint, path: "/nexus/models", token: token)
        guard list.models.count <= 100, list.models.allSatisfy(\.valid),
              Set(list.models.map(\.id)).count == list.models.count else {
            throw PS5NexusError.invalidResponse
        }
        return list.models
    }

    public func status(endpoint: PS5NexusEndpoint, token: String) async throws -> PS5NexusStatus {
        let result: PS5NexusStatus = try await send(endpoint: endpoint, path: "/nexus/status", token: token)
        guard result.state.utf8.count <= 80, (result.model?.utf8.count ?? 0) <= 256,
              (result.contextSize ?? 0) >= 0, (result.contextSize ?? 0) <= 1_000_000 else {
            throw PS5NexusError.invalidResponse
        }
        return result
    }

    public func load(modelID: String, endpoint: PS5NexusEndpoint, token: String) async throws {
        guard PS5NexusModel(id: modelID, label: "valid", drive: "", fits: true, current: false).valid else {
            throw PS5NexusError.invalidResponse
        }
        try await action(endpoint: endpoint, path: "/nexus/models/\(modelID)/load", token: token)
    }

    public func unload(endpoint: PS5NexusEndpoint, token: String) async throws {
        try await action(endpoint: endpoint, path: "/nexus/models/unload", token: token)
    }

    /// Requests are always authenticated, small, non-redirecting and bounded.
    /// No token is retained in the client or logged.
    public func send<Response: Decodable & Sendable>(
        endpoint: PS5NexusEndpoint,
        path: String,
        method: String = "GET",
        token: String,
        body: Data? = nil,
        query: [URLQueryItem] = [],
        as responseType: Response.Type = Response.self
    ) async throws -> Response {
        let data = try await perform(endpoint: endpoint, path: path, method: method,
                                     token: token, body: body, query: query)
        guard let result = try? JSONDecoder().decode(responseType, from: data) else {
            throw PS5NexusError.invalidResponse
        }
        return result
    }

    public func rawResult(endpoint: PS5NexusEndpoint, path: String, method: String = "GET",
                          token: String, body: Data? = nil,
                          query: [URLQueryItem] = []) async throws -> Data {
        try await perform(endpoint: endpoint, path: path, method: method,
                          token: token, body: body, query: query)
    }

    private func perform(endpoint: PS5NexusEndpoint, path: String, method: String,
                         token: String, body: Data? = nil,
                         query: [URLQueryItem] = []) async throws -> Data {
        guard !token.isEmpty, token.utf8.count <= 16_384,
              !token.contains("\r"), !token.contains("\n") else { throw PS5NexusError.noCredential }
        guard ["GET", "POST", "PUT", "PATCH"].contains(method) else { throw PS5NexusError.invalidEndpoint }
        let patchRoute = PS5NexusPatchClient.isPatchRoute(path)
        let commandRoute = PS5NexusCommandClient.isCommandRoute(path)
        let bodyLimit = path == "/nexus/agent-runs" ? 2 * 1_024 * 1_024 : (patchRoute ? 512 * 1_024 : 16 * 1_024)
        guard (body?.count ?? 0) <= bodyLimit else { throw PS5NexusError.requestTooLarge }
        let url = try endpoint.url(path: path, query: query)
        // Agent runs are durable jobs. Submission and each status poll are
        // short requests; generation continues on Debian between polls.
        let patchExecution = (patchRoute || commandRoute) && method == "POST" &&
            (path.hasSuffix("/apply") || path.hasSuffix("/execute") || path.hasSuffix("/reconcile"))
        // Manual application includes current policy/root checks and one bounded
        // host call. Give that path time to return its durable receipt.
        let requestTimeout: TimeInterval = patchExecution ? 40 : 12
        let resourceTimeout: TimeInterval = patchExecution ? 45 : 16
        var request = URLRequest(url: url, timeoutInterval: requestTimeout)
        request.httpMethod = method
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.cachePolicy = .reloadIgnoringLocalCacheData
        if let body {
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = body
        }
        let settings = URLSessionConfiguration.ephemeral
        settings.timeoutIntervalForRequest = requestTimeout
        settings.timeoutIntervalForResource = resourceTimeout
        settings.urlCache = nil
        settings.httpCookieStorage = nil
        settings.httpShouldSetCookies = false
        let data: Data
        let http: HTTPURLResponse
        do {
            let responseLimit = (path.hasPrefix("/nexus/agent-runs") || patchRoute || commandRoute) ? 3 * 1_024 * 1_024 : 128 * 1_024
            let loaded = try await AIHTTPResponseLoader.load(request, maximumBytes: responseLimit,
                                                            configuration: settings)
            guard let response = loaded.1 as? HTTPURLResponse else { throw PS5NexusError.invalidResponse }
            data = loaded.0
            http = response
        } catch AIConnectionError.responseTooLarge {
            throw PS5NexusError.responseTooLarge
        } catch AIConnectionError.httpStatus(let code) {
            throw Self.httpFailure(code, method: method, path: path)
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            // Keep transport failures generic: no response bodies, URLs or
            // credential-bearing descriptions are shown in the UI.
            throw PS5NexusError.unavailable
        }
        if !(200..<300).contains(http.statusCode) {
            throw Self.httpFailure(http.statusCode, method: method, path: path)
        }
        return data
    }

    static func httpFailure(_ code: Int, method: String, path: String) -> PS5NexusError {
        switch code {
        case 401: .unauthorized
        case 403: .forbidden
        case 404 where PS5NexusPatchClient.isPatchRoute(path) || PS5NexusCommandClient.isCommandRoute(path): .patchNotFound
        case 409 where PS5NexusPatchClient.isPatchRoute(path) || PS5NexusCommandClient.isCommandRoute(path): .patchReviewConflict
        case 404 where method == "GET" && path.hasPrefix("/nexus/agent-runs/"): .runNotFound
        case 410 where method == "POST" && path == "/nexus/agent-runs": .runExpired
        case 404, 501, 503: .unavailable
        default: .failed(code)
        }
    }

    public func action(endpoint: PS5NexusEndpoint, path: String, token: String) async throws {
        // 202 Accepted is allowed to have an empty body.
        _ = try await perform(endpoint: endpoint, path: path, method: "POST", token: token)
    }
}

public enum PS5NexusHost: String, CaseIterable, Identifiable, Codable, Sendable {
    case debian, nixos
    public var id: String { rawValue }
    public var title: String { rawValue == "debian" ? "Debian" : "NixOS" }
}

public struct PS5NexusWorkspace: Codable, Identifiable, Equatable, Sendable {
    public let id: String
    public let name: String
    public var readOnly: Bool? = nil
    public var generation: String? = nil
    public var capabilities: [String]? = nil
    enum CodingKeys: String, CodingKey {
        case id, name, capabilities, generation
        case readOnly = "read_only"
    }

    public func supports(_ operation: PS5NexusSubagentOperation) -> Bool {
        guard valid else { return false }
        if let capabilities { return capabilities.contains(operation.rawValue) }
        return operation == .inventory || operation == .findText
    }

    public var valid: Bool {
        !id.isEmpty && id.utf8.count <= 96 &&
            id.utf8.allSatisfy { (48...57).contains($0) || (65...90).contains($0) ||
                (97...122).contains($0) || $0 == 45 || $0 == 95 } &&
            !name.isEmpty && name.utf8.count <= 160 &&
            (generation.map { PS5NexusPatchValidation.hex($0, count: 64) } ?? true) &&
            (readOnly != false || (generation != nil && capabilities?.contains("apply_patch") == true)) &&
            (capabilities.map { values in
                values.count <= 9 && values.allSatisfy {
                    $0 == "list" || $0 == "read_file" || $0 == "apply_patch" ||
                    $0 == "run_command" || PS5NexusSubagentOperation(rawValue: $0) != nil
                }
            } ?? true)
    }
}

public struct PS5NexusWorkspaceList: Codable, Equatable, Sendable {
    public let host: String
    public let workspaces: [PS5NexusWorkspace]
}

public struct PS5NexusWorkspaceEntry: Codable, Equatable, Sendable, Identifiable {
    public let name: String
    public let path: String
    public let kind: String
    public var id: String { path }
}

public struct PS5NexusWorkspaceFiles: Codable, Equatable, Sendable {
    public let host: String
    public let workspaceID: String
    public let path: String
    public let entries: [PS5NexusWorkspaceEntry]
    public let truncated: Bool
    enum CodingKeys: String, CodingKey {
        case host, path, entries, truncated
        case workspaceID = "workspace_id"
    }
}

public struct PS5NexusWorkspaceContext: Codable, Equatable, Sendable {
    public let host: String
    public let workspaceID: String
    public let path: String
    public let text: String
    public let sizeBytes: Int
    enum CodingKeys: String, CodingKey {
        case host, path, text
        case workspaceID = "workspace_id"
        case sizeBytes = "size_bytes"
    }
}

public enum PS5NexusSubagentOperation: String, CaseIterable, Identifiable, Hashable, Codable, Sendable {
    case inventory, findText = "find_text"
    case gitStatus = "git_status", gitDiff = "git_diff", gitDiffStaged = "git_diff_staged"
    public var id: String { rawValue }
    public var title: String {
        switch self {
        case .inventory: "Inventory"
        case .findText: "Find text"
        case .gitStatus: "Git status"
        case .gitDiff: "Working tree diff"
        case .gitDiffStaged: "Staged diff"
        }
    }
    public var requiresFilePath: Bool { self == .gitDiff || self == .gitDiffStaged }
    public var isGit: Bool { self == .gitStatus || requiresFilePath }
}

public struct PS5NexusGitChange: Codable, Equatable, Sendable, Identifiable {
    public let path: String
    public let index: String
    public let worktree: String
    public var id: String { path }
}

public struct PS5NexusGitResult: Codable, Equatable, Sendable {
    public let path: String
    public let changes: [PS5NexusGitChange]
    public let diff: String
    public let truncated: Bool
}

private struct PS5NexusSubagentRequest: Encodable {
    let host: String
    let workspaceID: String
    let operation: String
    let path: String
    let query: String
    enum CodingKeys: String, CodingKey {
        case host, operation, path, query
        case workspaceID = "workspace_id"
    }
}

public struct PS5NexusWorkspaceClient: Sendable {
    private let http = PS5NexusHTTPClient()
    public init() {}

    public static func validRelativePath(_ path: String) -> Bool {
        let parts = path.split(separator: "/", omittingEmptySubsequences: false)
        return path.utf8.count <= 512 && !path.hasPrefix("/") &&
            !path.contains("\0") && !path.contains("\\") && !path.contains("\r") && !path.contains("\n") &&
            (path.isEmpty || (parts.count <= 12 && !parts.contains {
                $0.isEmpty || $0.hasPrefix(".") || $0.utf8.count > 255
            }))
    }

    public func list(endpoint: PS5NexusEndpoint, token: String,
                     host: PS5NexusHost) async throws -> [PS5NexusWorkspace] {
        let result: PS5NexusWorkspaceList = try await http.send(
            endpoint: endpoint, path: "/nexus/workspaces/\(host.rawValue)", token: token)
        guard result.host == host.rawValue, result.workspaces.count <= 100,
              result.workspaces.allSatisfy(\.valid),
              Set(result.workspaces.map(\.id)).count == result.workspaces.count else {
            throw PS5NexusError.invalidResponse
        }
        return result.workspaces
    }

    public func files(endpoint: PS5NexusEndpoint, token: String, host: PS5NexusHost,
                      workspace: PS5NexusWorkspace, path: String = "") async throws -> PS5NexusWorkspaceFiles {
        guard workspace.valid, Self.validRelativePath(path) else { throw PS5NexusError.invalidEndpoint }
        let result: PS5NexusWorkspaceFiles = try await http.send(
            endpoint: endpoint, path: "/nexus/workspaces/\(host.rawValue)/\(workspace.id)/files", token: token,
            query: [URLQueryItem(name: "path", value: path)])
        guard result.host == host.rawValue, result.workspaceID == workspace.id,
              result.entries.count <= 250, Self.validRelativePath(result.path),
              result.entries.allSatisfy({ Self.validRelativePath($0.path) && $0.name.utf8.count <= 160 }) else {
            throw PS5NexusError.invalidResponse
        }
        return result
    }

    public func context(endpoint: PS5NexusEndpoint, token: String, host: PS5NexusHost,
                        workspace: PS5NexusWorkspace, path: String) async throws -> PS5NexusWorkspaceContext {
        guard workspace.valid, !path.isEmpty, Self.validRelativePath(path) else {
            throw PS5NexusError.invalidEndpoint
        }
        let result: PS5NexusWorkspaceContext = try await http.send(
            endpoint: endpoint, path: "/nexus/workspaces/\(host.rawValue)/\(workspace.id)/context", token: token,
            query: [URLQueryItem(name: "path", value: path)])
        guard result.host == host.rawValue, result.workspaceID == workspace.id,
              result.path == path, result.text.utf8.count <= 100 * 1_024,
              (0...100 * 1_024).contains(result.sizeBytes) else { throw PS5NexusError.invalidResponse }
        return result
    }

    /// Synchronous read-only workspace operations only. No arbitrary
    /// commands or tool payload execution are ever sent by Nexus.
    public func task(endpoint: PS5NexusEndpoint, token: String, host: PS5NexusHost,
                     workspace: PS5NexusWorkspace, operation: PS5NexusSubagentOperation,
                     path: String = "", query: String = "") async throws -> String {
        let result = try await taskResponse(endpoint: endpoint, token: token, host: host,
            workspace: workspace, operation: operation, path: path, query: query)
        guard let text = String(data: result, encoding: .utf8) else { throw PS5NexusError.invalidResponse }
        return text.count > 12_000 ? String(text.prefix(12_000)) + "\n… Display shortened." : text
    }

    public func gitInspection(endpoint: PS5NexusEndpoint, token: String, host: PS5NexusHost,
                              workspace: PS5NexusWorkspace, operation: PS5NexusSubagentOperation,
                              path: String) async throws -> PS5NexusGitResult {
        guard operation.isGit else { throw PS5NexusError.invalidEndpoint }
        let response = try await taskResponse(endpoint: endpoint, token: token, host: host,
            workspace: workspace, operation: operation, path: path, query: "")
        struct Envelope: Decodable { let git: PS5NexusGitResult }
        let result = try JSONDecoder().decode(Envelope.self, from: response).git
        guard result.path == path, result.changes.count <= 128,
              Set(result.changes.map(\.path)).count == result.changes.count,
              result.diff.utf8.count <= 64 * 1_024, !result.diff.contains("\0"),
              (operation == .gitStatus ? result.diff.isEmpty : result.changes.isEmpty),
              result.changes.allSatisfy({ change in
                  Self.validRelativePath(change.path) && !change.path.isEmpty &&
                  (path.isEmpty || change.path.hasPrefix(path + "/")) &&
                  [change.index, change.worktree].allSatisfy { value in
                      value.count == 1 && " MADTURC".contains(value)
                  }
              }) else { throw PS5NexusError.invalidResponse }
        return result
    }

    private func taskResponse(endpoint: PS5NexusEndpoint, token: String, host: PS5NexusHost,
                              workspace: PS5NexusWorkspace, operation: PS5NexusSubagentOperation,
                              path: String, query: String) async throws -> Data {
        guard workspace.valid, workspace.supports(operation), Self.validRelativePath(path),
              (!operation.requiresFilePath || !path.isEmpty),
              query.utf8.count <= 256,
              (operation == .findText || query.isEmpty),
              (operation != .findText || !query.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty) else {
            throw PS5NexusError.invalidEndpoint
        }
        let request = PS5NexusSubagentRequest(host: host.rawValue, workspaceID: workspace.id,
                                               operation: operation.rawValue, path: path, query: query)
        let body = try JSONEncoder().encode(request)
        let result = try await http.rawResult(endpoint: endpoint,
                                              path: "/nexus/workspaces/\(host.rawValue)/\(workspace.id)/tasks",
                                              method: "POST", token: token, body: body)
        guard result.count <= 128 * 1_024,
              let object = try? JSONSerialization.jsonObject(with: result),
              let object = object as? [String: Any],
              object["host"] as? String == host.rawValue,
              object["workspace_id"] as? String == workspace.id,
              object["operation"] as? String == operation.rawValue,
              object["status"] as? String == "completed" else {
            throw PS5NexusError.invalidResponse
        }
        return result
    }
}

public struct PS5NexusOrchestratedMessage: Codable, Equatable, Sendable {
    public let role: String
    public let content: String
}

public let ps5NexusPromptByteLimit = 48 * 1_024

/// A user-visible orchestrator turn. This remains separate from compacted model
/// context so checkpointing never replaces the locally retained transcript.
public struct PS5NexusOrchestratedTurn: Codable, Equatable, Identifiable, Sendable {
    public let id: UUID
    public let prompt: String
    public let response: String?
    public let model: String?
    public let finishReason: String?
    public let status: String
    public let createdAt: Date

    public init(id: UUID = UUID(), prompt: String, response: String? = nil,
                model: String? = nil, finishReason: String? = nil,
                status: String, createdAt: Date = .now) {
        self.id = id
        self.prompt = prompt
        self.response = response
        self.model = model
        self.finishReason = finishReason
        self.status = status
        self.createdAt = createdAt
    }

    public var isValid: Bool {
        !prompt.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && prompt.utf8.count <= ps5NexusPromptByteLimit &&
            (response?.utf8.count ?? 0) <= ps5NexusMessageByteLimit && (model?.utf8.count ?? 0) <= 256 &&
            (finishReason.map { ps5NexusFinishReasons.contains($0) } ?? true) &&
            ["completed", "cancelled", "failed", "unavailable"].contains(status)
    }
}

/// Exact request snapshot retained before submission, allowing a lost reply to
/// be retried with the same identifier and without changing its meaning.
public enum PS5NexusRunScope {
    /// Bind a persisted request to the exact validated gateway URL and selected
    /// workspace generation without retaining an endpoint address or token in
    /// the saved request. A change in any part requires fresh owner review.
    public static func fingerprint(endpoint: PS5NexusEndpoint, host: PS5NexusHost,
                                   workspace: PS5NexusWorkspace, path: String) -> String {
        let source = [endpoint.baseURL.absoluteString, host.rawValue, workspace.id,
                      workspace.generation ?? "", path].joined(separator: "\u{0}")
        return SHA256.hash(data: Data(source.utf8)).map {
            String(format: "%02x", Int($0))
        }.joined()
    }
}

public enum PS5NexusAgentEngine: String, Codable, CaseIterable, Sendable {
    case nexus, hermes
}

public struct PS5NexusPendingSubmission: Codable, Equatable, Sendable {
    public let id: String
    /// Random local Keychain-backed identity for the exact gateway credential.
    /// Legacy nil identities may be displayed but are never retried.
    public let credentialIdentity: UUID?
    /// Digest of validated gateway origin and exact workspace/path generation.
    public let scopeFingerprint: String?
    public let prompt: String
    public let history: [PS5NexusOrchestratedMessage]
    public let subagents: Int
    public let autoCompact: Bool
    public let compactOnly: Bool?
    public let allowProposals: Bool?
    public let engine: PS5NexusAgentEngine?

    public init(id: String, prompt: String, history: [PS5NexusOrchestratedMessage],
                subagents: Int, autoCompact: Bool, compactOnly: Bool? = nil, allowProposals: Bool? = nil,
                engine: PS5NexusAgentEngine? = nil, credentialIdentity: UUID? = nil,
                scopeFingerprint: String? = nil) {
        self.id = id
        self.credentialIdentity = credentialIdentity
        self.scopeFingerprint = scopeFingerprint
        self.prompt = prompt
        self.history = history
        self.subagents = subagents
        self.autoCompact = autoCompact
        self.compactOnly = compactOnly
        self.allowProposals = allowProposals
        self.engine = engine
    }

    public var isValid: Bool {
        id.utf8.count == 32 && id.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) } &&
        (scopeFingerprint.map { PS5NexusPatchValidation.hex($0, count: 64) } ?? true) &&
        !prompt.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && prompt.utf8.count <= ps5NexusPromptByteLimit &&
        (0...3).contains(subagents) && (!(compactOnly ?? false) || !(allowProposals ?? false)) && (!(compactOnly ?? false) || (subagents == 0 && !history.isEmpty)) && history.count <= 32 && history.allSatisfy {
            ["user", "assistant"].contains($0.role) && $0.content.utf8.count <= ps5NexusMessageByteLimit
        }
    }
}

public struct PS5NexusCompactionRecord: Codable, Equatable, Identifiable, Sendable {
    public let id: UUID
    public let summary: String
    public let createdAt: Date

    public init(id: UUID = UUID(), summary: String, createdAt: Date = .now) {
        self.id = id
        self.summary = summary
        self.createdAt = createdAt
    }

    public var isValid: Bool {
        !summary.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty &&
            summary.utf8.count <= ps5NexusMessageByteLimit
    }
}

/// Full local transcript plus the separate, compactable context sent to the model.
public struct PS5NexusOrchestratedConversation: Codable, Equatable, Sendable {
    public var turns: [PS5NexusOrchestratedTurn]
    public var contextHistory: [PS5NexusOrchestratedMessage]
    public var pendingPrompt: String?
    public var pendingSubmission: PS5NexusPendingSubmission?
    /// Owner credential that last populated the compactable model context.
    /// Not a token or remote identity; legacy nil history must be reset before use.
    public var credentialIdentity: UUID?
    public var scopeFingerprint: String?
    // Optional preserves decoding for conversations saved before this field existed.
    public var compactions: [PS5NexusCompactionRecord]?
    /// Nil preserves the automatic default for older saved conversations.
    public var automaticCompactionEnabled: Bool?
    public var updatedAt: Date

    public init(turns: [PS5NexusOrchestratedTurn] = [],
                contextHistory: [PS5NexusOrchestratedMessage] = [],
                pendingPrompt: String? = nil, pendingSubmission: PS5NexusPendingSubmission? = nil,
                compactions: [PS5NexusCompactionRecord]? = nil, credentialIdentity: UUID? = nil,
                scopeFingerprint: String? = nil,
                automaticCompactionEnabled: Bool? = nil,
                updatedAt: Date = .now) {
        self.turns = turns
        self.contextHistory = contextHistory
        self.pendingPrompt = pendingPrompt
        self.pendingSubmission = pendingSubmission
        self.credentialIdentity = credentialIdentity
        self.scopeFingerprint = scopeFingerprint
        self.compactions = compactions
        self.automaticCompactionEnabled = automaticCompactionEnabled
        self.updatedAt = updatedAt
    }

    /// A submitted task keeps its original policy throughout durable recovery.
    public var effectiveAutomaticCompaction: Bool {
        pendingSubmission?.autoCompact ?? automaticCompactionEnabled ?? true
    }

    public var isValid: Bool {
        turns.allSatisfy(\.isValid) && (compactions?.allSatisfy(\.isValid) ?? true) &&
            (scopeFingerprint.map { PS5NexusPatchValidation.hex($0, count: 64) } ?? true) &&
            contextHistory.count <= 32 && contextHistory.allSatisfy {
                ["user", "assistant"].contains($0.role) && $0.content.utf8.count <= ps5NexusMessageByteLimit
            } && (pendingPrompt?.utf8.count ?? 0) <= ps5NexusPromptByteLimit &&
            (pendingSubmission.map {
                $0.isValid && $0.prompt == pendingPrompt && $0.history == contextHistory &&
                ($0.credentialIdentity == nil || $0.credentialIdentity == credentialIdentity) &&
                ($0.scopeFingerprint == nil || $0.scopeFingerprint == scopeFingerprint)
            } ?? true)
    }

    /// Never attach context from a previous or unknown credential to a fresh
    /// remote submission or replace an unresolved durable task. Empty context
    /// with no pending request is safe to bind to a new session.
    public func canSendContext(credential identity: UUID, scope: String) -> Bool {
        isValid && pendingSubmission == nil && pendingPrompt == nil &&
            PS5NexusPatchValidation.hex(scope, count: 64) &&
            (contextHistory.isEmpty || (credentialIdentity == identity && scopeFingerprint == scope))
    }

    /// Read-only server reattachment is possible after a token refresh for
    /// the same owner, but never through a different endpoint or root.
    public func canReadSavedRun(runID: String, scope: String) -> Bool {
        isValid && PS5NexusPatchValidation.hex(scope, count: 64) &&
            pendingSubmission?.id == runID &&
            scopeFingerprint == scope && pendingSubmission?.scopeFingerprint == scope
    }

    /// A lost-reply retry must prove both the persisted request and its model
    /// context belong to the *same* original Keychain credential. No implicit
    /// replay after sign-out, token refresh, or legacy migration.
    public func canResume(runID: String, credential identity: UUID, scope: String) -> Bool {
        canReadSavedRun(runID: runID, scope: scope) && credentialIdentity == identity &&
            pendingSubmission?.id == runID && pendingSubmission?.credentialIdentity == identity
    }
}

public struct PS5NexusOrchestratedSubagent: Codable, Equatable, Sendable {
    public let role: String
    public let output: String
}

public struct PS5NexusOrchestratedWorkspace: Codable, Equatable, Sendable {
    public let host: String
    public let workspaceID: String
    public let path: String
    enum CodingKeys: String, CodingKey {
        case host, path
        case workspaceID = "workspace_id"
    }
    public init(host: PS5NexusHost, workspaceID: String, path: String) {
        self.host = host.rawValue
        self.workspaceID = workspaceID
        self.path = path
    }
}

public struct PS5NexusWorkspaceToolEvent: Codable, Equatable, Sendable {
    public let tool: String
    public let path: String
    public let resultCount: Int
    public var status: String? = nil
    public var changesApplied: Bool? = nil
    enum CodingKeys: String, CodingKey {
        case tool, path, status
        case changesApplied = "changes_applied"
        case resultCount = "result_count"
    }
}

private struct PS5NexusOrchestratedRequest: Encodable {
    let prompt: String
    let history: [PS5NexusOrchestratedMessage]
    let workspace: PS5NexusOrchestratedWorkspace
    let subagents: Int
    let autoCompact: Bool
    let submissionID: String?
    let compactOnly: Bool?
    let allowProposals: Bool?
    let engine: PS5NexusAgentEngine?
    enum CodingKeys: String, CodingKey {
        case prompt, history, workspace, subagents, engine
        case autoCompact = "auto_compact"
        case submissionID = "submission_id"
        case compactOnly = "compact_only"
        case allowProposals = "allow_proposals"
    }
}

public struct PS5NexusOrchestratedResult: Codable, Equatable, Sendable {
    public let response: String
    public let model: String
    public let compacted: Bool
    public let finishReason: String?
    public let inputTokens: Int?
    public let reservedOutputTokens: Int?
    public let contextWindowTokens: Int?
    public let workspaceTools: [PS5NexusWorkspaceToolEvent]?
    public let historyForNextTurn: [PS5NexusOrchestratedMessage]
    public let subagents: [PS5NexusOrchestratedSubagent]
    public let workspace: PS5NexusOrchestratedWorkspace
    enum CodingKeys: String, CodingKey {
        case response, model, compacted, subagents, workspace
        case inputTokens = "input_tokens"
        case finishReason = "finish_reason"
        case reservedOutputTokens = "reserved_output_tokens"
        case contextWindowTokens = "context_window_tokens"
        case workspaceTools = "workspace_tools"
        case historyForNextTurn = "history_for_next_turn"
    }
}

private struct PS5NexusRunSubmission: Decodable, Sendable {
    let id: String
    let status: String
}

public struct PS5NexusRunSubagentProgress: Decodable, Equatable, Identifiable, Sendable {
    public let id: String
    public let role: String
    public let status: String
}

public struct PS5NexusRunEvent: Decodable, Equatable, Identifiable, Sendable {
    public let at: TimeInterval
    public let phase: String
    public let status: String?
    public let subagentIndex: Int?
    public let subagentStatus: String?
    public var id: String { "\(at)-\(phase)-\(subagentIndex ?? -1)" }

    enum CodingKeys: String, CodingKey {
        case at, phase, status
        case subagentIndex = "subagent_index"
        case subagentStatus = "subagent_status"
    }
}

public enum PS5NexusApprovalKind: String, Decodable, Sendable {
    case patch
    case command
}

public struct PS5NexusRunProgress: Decodable, Sendable {
    public let id: String
    public let status: String
    public let phase: String
    public let result: PS5NexusOrchestratedResult?
    public let error: String?
    public let subagents: [PS5NexusRunSubagentProgress]
    public let events: [PS5NexusRunEvent]?
    public let approvalID: String?
    public let approvalKind: PS5NexusApprovalKind?

    enum CodingKeys: String, CodingKey {
        case id, status, phase, result, error, subagents, events
        case approvalID = "approval_id"
        case approvalKind = "approval_kind"
    }
}

public struct PS5NexusOrchestratorClient: Sendable {
    private let http = PS5NexusHTTPClient()
    public init() {}

    @MainActor public func submit(endpoint: PS5NexusEndpoint, token: String, prompt: String,
                    workspace: PS5NexusWorkspace, host: PS5NexusHost, path: String,
                    history: [PS5NexusOrchestratedMessage] = [], subagents: Int = 0,
                    autoCompact: Bool = true, submissionID: String? = nil,
                    compactOnly: Bool = false, allowProposals: Bool = false,
                    engine: PS5NexusAgentEngine = .nexus) async throws -> String {
        guard workspace.valid, PS5NexusWorkspaceClient.validRelativePath(path),
              !prompt.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              prompt.utf8.count <= ps5NexusPromptByteLimit, (0...3).contains(subagents),
              !compactOnly || (subagents == 0 && !history.isEmpty && !allowProposals),
              history.count <= 32, submissionID.map({ $0.utf8.count == 32 &&
                  $0.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) } }) ?? true,
              history.allSatisfy({ ["user", "assistant", "system"].contains($0.role) &&
                  $0.content.utf8.count <= ps5NexusMessageByteLimit }) else {
            throw PS5NexusError.requestTooLarge
        }
        let requestedWorkspace = PS5NexusOrchestratedWorkspace(
            host: host, workspaceID: workspace.id, path: path)
        let request = PS5NexusOrchestratedRequest(prompt: prompt, history: history,
            workspace: requestedWorkspace, subagents: subagents, autoCompact: autoCompact,
            submissionID: submissionID, compactOnly: compactOnly ? true : nil,
            allowProposals: allowProposals ? true : nil,
            engine: engine == .nexus ? nil : engine)
        let body = try JSONEncoder().encode(request)
        let submission: PS5NexusRunSubmission = try await http.send(
            endpoint: endpoint, path: "/nexus/agent-runs",
            method: "POST", token: token, body: body)
        guard submission.id.utf8.count == 32,
              submission.id.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
              (submissionID == nil || submission.id == submissionID),
              ["queued", "running", "waiting_for_approval", "cancelling", "completed", "failed", "cancelled"].contains(submission.status) else {
            throw PS5NexusError.invalidResponse
        }
        return submission.id
    }

    @MainActor public func run(endpoint: PS5NexusEndpoint, token: String, prompt: String,
                    workspace: PS5NexusWorkspace, host: PS5NexusHost, path: String,
                    history: [PS5NexusOrchestratedMessage] = [], subagents: Int = 0,
                    autoCompact: Bool = true) async throws -> PS5NexusOrchestratedResult {
        let runID = try await submit(endpoint: endpoint, token: token, prompt: prompt,
            workspace: workspace, host: host, path: path, history: history,
            subagents: subagents, autoCompact: autoCompact)
        return try await wait(endpoint: endpoint, token: token, runID: runID,
                              host: host, workspace: workspace, path: path)
    }

    @MainActor public func wait(endpoint: PS5NexusEndpoint, token: String, runID: String,
                     host: PS5NexusHost, workspace: PS5NexusWorkspace, path: String,
                     onProgress: @escaping @MainActor @Sendable (PS5NexusRunProgress) -> Void = { _ in }) async throws -> PS5NexusOrchestratedResult {
        guard runID.utf8.count == 32,
              runID.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
              workspace.valid, PS5NexusWorkspaceClient.validRelativePath(path) else {
            throw PS5NexusError.invalidEndpoint
        }
        // Keep polling below the gateway's per-subject request budget while
        // tolerating long local-model generations (up to about an hour).
        for _ in 0..<900 {
            try Task.checkCancellation()
            let state: PS5NexusRunProgress = try await http.send(
                endpoint: endpoint, path: "/nexus/agent-runs/\(runID)",
                method: "GET", token: token)
            guard state.id == runID, state.subagents.count <= 3,
                  state.subagents.allSatisfy({ $0.id.utf8.count == 32 &&
                      $0.id.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) &&
                      ["queued", "running", "cancelling", "completed", "cancelled"].contains($0.status) }),
                  ["queued", "running", "waiting_for_approval", "cancelling", "completed", "failed", "cancelled"].contains(state.status),
                  state.approvalID.map({ PS5NexusPatchValidation.hex($0, count: 32) }) ?? true,
                  state.phase.utf8.count <= 120 else {
                throw PS5NexusError.invalidResponse
            }
            onProgress(state)
            if state.status == "completed", let result = state.result {
                try Self.validate(result, host: host, workspace: workspace, path: path)
                return result
            }
            if state.status == "failed" || state.status == "cancelled" {
                if state.status == "cancelled" { throw PS5NexusError.cancelled }
                throw PS5NexusError.runFailed
            }
            try await Task.sleep(for: .seconds(4))
        }
        throw PS5NexusError.unavailable
    }

    @MainActor public func cancel(endpoint: PS5NexusEndpoint, token: String, runID: String,
                       subagentID: String? = nil) async throws {
        guard runID.utf8.count == 32,
              runID.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else {
            throw PS5NexusError.invalidEndpoint
        }
        let suffix: String
        if let subagentID {
            guard subagentID.utf8.count == 32,
                  subagentID.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else {
                throw PS5NexusError.invalidEndpoint
            }
            suffix = "/subagents/\(subagentID)/cancel"
        } else {
            suffix = "/cancel"
        }
        let _: PS5NexusRunProgress = try await http.send(
            endpoint: endpoint, path: "/nexus/agent-runs/\(runID)\(suffix)",
            method: "POST", token: token)
    }

    private static func validate(_ result: PS5NexusOrchestratedResult, host: PS5NexusHost,
                                 workspace: PS5NexusWorkspace, path: String) throws {
        guard result.response.utf8.count <= ps5NexusMessageByteLimit,
              result.finishReason.map({ ps5NexusFinishReasons.contains($0) }) ?? true,
              result.model.utf8.count <= 256,
              result.subagents.count <= 3,
              result.subagents.allSatisfy({ $0.role.utf8.count <= 80 && $0.output.utf8.count <= 16_384 }),
              result.historyForNextTurn.count <= 32,
              result.historyForNextTurn.allSatisfy({ ["user", "assistant", "system"].contains($0.role) &&
                  $0.content.utf8.count <= ps5NexusMessageByteLimit }),
              result.workspace.host == host.rawValue,
              result.workspace.workspaceID == workspace.id,
              result.workspace.path == path else {
            throw PS5NexusError.invalidResponse
        }
    }
}

/// GET /v1/nexus/models
public struct PS5NexusModel: Codable, Identifiable, Equatable, Sendable {
    public let id: String
    public let label: String
    public let drive: String
    public let fits: Bool
    public let current: Bool
    public let architecture: String?
    public let fileSizeBytes: UInt64?
    /// GGUF general.file_type, which describes the file, not every tensor.
    public let quantizationType: UInt32?

    public init(id: String, label: String, drive: String, fits: Bool, current: Bool,
                architecture: String? = nil, fileSizeBytes: UInt64? = nil, quantizationType: UInt32? = nil) {
        self.id = id
        self.label = label
        self.drive = drive
        self.fits = fits
        self.current = current
        self.architecture = architecture
        self.fileSizeBytes = fileSizeBytes
        self.quantizationType = quantizationType
    }

    enum CodingKeys: String, CodingKey {
        case id, label, drive, fits, current, architecture
        case fileSizeBytes = "file_size_bytes"
        case quantizationType = "quantization_type"
    }

    /// Names from the pinned llama_ftype enum; never inferred from a filename.
    public var quantizationName: String? {
        guard let quantizationType, quantizationType != 1024 else { return nil }
        let names: [UInt32: String] = [
            0: "F32", 1: "F16", 2: "Q4_0", 3: "Q4_1", 7: "Q8_0", 8: "Q5_0", 9: "Q5_1",
            10: "Q2_K", 11: "Q3_K_S", 12: "Q3_K_M", 13: "Q3_K_L", 14: "Q4_K_S", 15: "Q4_K_M",
            16: "Q5_K_S", 17: "Q5_K_M", 18: "Q6_K", 19: "IQ2_XXS", 20: "IQ2_XS", 21: "Q2_K_S",
            22: "IQ3_XS", 23: "IQ3_XXS", 24: "IQ1_S", 25: "IQ4_NL", 26: "IQ3_S", 27: "IQ3_M",
            28: "IQ2_S", 29: "IQ2_M", 30: "IQ4_XS", 31: "IQ1_M", 32: "BF16", 36: "TQ1_0",
            37: "TQ2_0", 38: "MXFP4_MOE", 39: "NVFP4", 40: "Q1_0", 41: "Q2_0"
        ]
        return names[quantizationType] ?? "Unknown GGUF type \(quantizationType)"
    }

    public var valid: Bool {
        id.utf8.count == 16 && id.utf8.allSatisfy {
            (48...57).contains($0) || (97...102).contains($0)
        } && !label.isEmpty && label.utf8.count <= 256 && drive.utf8.count <= 128 &&
            (fileSizeBytes.map { $0 > 0 && $0 <= 9_007_199_254_740_991 } ?? true) &&
            quantizationType != 1024 &&
            (architecture.map {
                !$0.isEmpty && $0.utf8.count <= 64 && $0.utf8.allSatisfy {
                    (65...90).contains($0) || (97...122).contains($0) ||
                        (48...57).contains($0) || [45, 46, 95].contains($0)
                }
            } ?? true)
    }
}

public struct PS5NexusModelList: Codable, Equatable, Sendable {
    public let models: [PS5NexusModel]
}

/// GET /v1/nexus/status
public struct PS5NexusStatus: Codable, Equatable, Sendable {
    public let state: String
    public let modelID: String?
    public let model: String?
    public let contextSize: Int?
    public let contextUsed: Int?
    public let generationTPS: Double?
    public let promptTPS: Double?
    public let memoryPoolGiB: Double?
    public let memoryFreeGiB: Double?
    public let modelGiB: Double?
    public let kvCacheGiB: Double?
    public let loadProgress: Double?
    public let ready: Bool

    enum CodingKeys: String, CodingKey {
        case state, model, ready
        case modelID = "model_id"
        case contextSize = "context_size"
        case contextUsed = "context_used"
        case generationTPS = "generation_tps"
        case promptTPS = "prompt_tps"
        case memoryPoolGiB = "memory_pool_gib"
        case memoryFreeGiB = "memory_free_gib"
        case modelGiB = "model_gib"
        case kvCacheGiB = "kv_cache_gib"
        case loadProgress = "load_progress"
    }
}

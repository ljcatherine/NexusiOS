import Foundation
import Crypto

/// Review records bind immutable source snapshots and optional managed-root identity.
public struct PS5NexusPatchProposal: Codable, Equatable, Sendable {
    public let host: String
    public let workspaceID: String
    public let path: String
    public let baseSHA256: String
    public let original: String
    public let replacement: String
    public var workspaceGeneration: String? = nil

    enum CodingKeys: String, CodingKey {
        case host, path, original, replacement
        case workspaceID = "workspace_id", baseSHA256 = "base_sha256"
        case workspaceGeneration = "workspace_generation"
    }

    var valid: Bool {
        PS5NexusPatchValidation.validScope(host: host, workspaceID: workspaceID) &&
        PS5NexusPatchValidation.validPath(path) &&
        original.utf8.count <= 65_536 && replacement.utf8.count <= 65_536 &&
        !original.contains("\0") && !replacement.contains("\0") &&
        baseSHA256 == Self.hash(original) &&
        (workspaceGeneration.map { PS5NexusPatchValidation.hex($0, count: 64) } ?? true)
    }

    /// Matches Python json.dumps(ensure_ascii=False, sort_keys=True, separators=(",", ":")).
    /// An explicit string encoder avoids platform-specific slash and Unicode escaping.
    var digest: String {
        var fields = [("base_sha256", baseSHA256), ("host", host), ("original", original),
                      ("path", path), ("replacement", replacement), ("workspace_id", workspaceID)]
        if let workspaceGeneration { fields.append(("workspace_generation", workspaceGeneration)) }
        fields.sort { $0.0 < $1.0 }
        return Self.hash("{" + fields.map { Self.quote($0.0) + ":" + Self.quote($0.1) }.joined(separator: ",") + "}")
    }

    private static func quote(_ value: String) -> String {
        var result = "\""
        for scalar in value.unicodeScalars {
            switch scalar.value {
            case 34: result += "\\\""
            case 92: result += "\\\\"
            case 8: result += "\\b"
            case 9: result += "\\t"
            case 10: result += "\\n"
            case 12: result += "\\f"
            case 13: result += "\\r"
            case 0..<32: result += String(format: "\\u%04x", scalar.value)
            default: result.unicodeScalars.append(scalar)
            }
        }
        return result + "\""
    }

    static func hash(_ value: String) -> String {
        SHA256.hash(data: Data(value.utf8)).map { String(format: "%02x", $0) }.joined()
    }
}

public struct PS5NexusPatchExecution: Codable, Equatable, Sendable {
    public let operationID: String
    public let phase: String
    public let resultSHA256: String?
    public let createdAt: Double
    public let updatedAt: Double
    enum CodingKeys: String, CodingKey {
        case phase
        case operationID = "operation_id", resultSHA256 = "result_sha256"
        case createdAt = "created_at", updatedAt = "updated_at"
    }
    func valid(replacement: String) -> Bool {
        PS5NexusPatchValidation.hex(operationID, count: 32) &&
        PS5NexusPatchValidation.executionPhases.contains(phase) &&
        createdAt.isFinite && updatedAt.isFinite && createdAt > 0 && updatedAt > 0 &&
        (phase == "applied" ? resultSHA256 == PS5NexusPatchProposal.hash(replacement) : resultSHA256 == nil)
    }
}

public struct PS5NexusPatchRecord: Codable, Equatable, Identifiable, Sendable {
    public let id: String
    public let digest: String
    public let proposal: PS5NexusPatchProposal
    public let createdAt: Double
    public let expiresAt: Double
    public let status: String
    public var execution: PS5NexusPatchExecution? = nil
    public var manualExecutionAllowed: Bool? = nil

    enum CodingKeys: String, CodingKey {
        case id, digest, proposal, status, execution
        case manualExecutionAllowed = "manual_execution_allowed"
        case createdAt = "created_at", expiresAt = "expires_at"
    }

    public var canReview: Bool { status == "pending" && expiresAt > Date().timeIntervalSince1970 }
    public var canApply: Bool {
        manualExecutionAllowed == true && proposal.workspaceGeneration != nil &&
        expiresAt > Date().timeIntervalSince1970 &&
        (status == "approved" || (status == "executing" && execution?.phase == "prepared"))
    }
    public var canReconcile: Bool {
        manualExecutionAllowed == true && status == "executing" &&
        execution.map { ["dispatching", "uncertain"].contains($0.phase) } == true
    }

    func valid(host: PS5NexusHost, workspaceID: String) -> Bool {
        proposal.valid && proposal.host == host.rawValue && proposal.workspaceID == workspaceID &&
        PS5NexusPatchValidation.hex(id, count: 32) && digest == proposal.digest &&
        PS5NexusPatchValidation.validTimes(createdAt, expiresAt) &&
        PS5NexusPatchValidation.statuses.contains(status) &&
        (manualExecutionAllowed != true || proposal.workspaceGeneration != nil) &&
        (execution.map { status == "executing" && $0.valid(replacement: proposal.replacement) } ?? true)
    }
}

public struct PS5NexusPatchSummary: Codable, Equatable, Identifiable, Sendable {
    public let id: String
    public let digest: String
    public let path: String
    public let baseSHA256: String
    public let createdAt: Double
    public let expiresAt: Double
    public let status: String
    public var executionPhase: String? = nil

    enum CodingKeys: String, CodingKey {
        case id, digest, path, status
        case executionPhase = "execution_phase"
        case baseSHA256 = "base_sha256", createdAt = "created_at", expiresAt = "expires_at"
    }

    var valid: Bool {
        PS5NexusPatchValidation.hex(id, count: 32) && PS5NexusPatchValidation.hex(digest, count: 64) &&
        PS5NexusPatchValidation.hex(baseSHA256, count: 64) && PS5NexusPatchValidation.validPath(path) &&
        PS5NexusPatchValidation.validTimes(createdAt, expiresAt) && PS5NexusPatchValidation.statuses.contains(status) &&
        (executionPhase.map { status == "executing" && PS5NexusPatchValidation.executionPhases.contains($0) } ?? true)
    }
}

/// Shared bounds for immutable proposal data, independent of HTTP or UI.
enum PS5NexusPatchValidation {
    static let executionPhases: Set<String> = ["prepared", "dispatching", "applied", "conflict", "failed", "uncertain"]
    static let statuses: Set<String> = ["pending", "approved", "rejected", "executing"]

    static func hex(_ value: String, count: Int) -> Bool {
        value.utf8.count == count && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
    static func validTimes(_ created: Double, _ expires: Double) -> Bool {
        created.isFinite && expires.isFinite && created > 0 && expires > created && expires - created <= 3_600
    }
    static func validScope(host: String, workspaceID: String) -> Bool {
        ["debian", "nixos"].contains(host) && workspaceID.range(of: "^[a-z][a-z0-9_-]{0,31}$", options: .regularExpression) == workspaceID.startIndex..<workspaceID.endIndex
    }
    static func validPath(_ path: String) -> Bool {
        !path.isEmpty && PS5NexusWorkspaceClient.validRelativePath(path)
    }
}

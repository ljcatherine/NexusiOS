import Foundation
import Crypto

/// Deterministic Python/Go wire binding. A displayed command must match its
/// human-approved SHA-256 digest, not merely carry a plausible 64-hex string.
enum PS5NexusCommandBinding {
    static func hash(_ bytes: Data) -> String {
        SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
    }
    static func quote(_ value: String, goHTML: Bool = false) -> String {
        var text = "\""
        for scalar in value.unicodeScalars {
            switch scalar.value {
            case 34: text += "\\\""
            case 92: text += "\\\\"
            case 8: text += "\\b"
            case 9: text += "\\t"
            case 10: text += "\\n"
            case 12: text += "\\f"
            case 13: text += "\\r"
            case 0..<32: text += String(format: "\\u%04x", scalar.value)
            case 38, 60, 62, 0x2028, 0x2029:
                if goHTML { text += String(format: "\\u%04x", scalar.value) }
                else { text.unicodeScalars.append(scalar) }
            default: text.unicodeScalars.append(scalar)
            }
        }
        return text + "\""
    }
    static func digest(_ value: String) -> String { hash(Data(value.utf8)) }
    static func manifest(_ inputs: [PS5NexusCommandInput]) -> String {
        let entries = inputs.map { entry in
            "{\"path\":\(quote(entry.path, goHTML: true)),\"size_bytes\":\(entry.sizeBytes),\"sha256\":\(quote(entry.sha256, goHTML: true))}"
        }
        return hash(Data("nexus.command.inputs.v1\0[\(entries.joined(separator: ","))]".utf8))
    }
}

/// Fixed-profile restricted commands use a *distinct* gateway review permission.
/// This API accepts no user-supplied shell, executable, arguments or source path.
public struct PS5NexusCommandInput: Codable, Equatable, Sendable {
    public let path: String
    public let sizeBytes: Int
    public let sha256: String
    enum CodingKeys: String, CodingKey {
        case path, sha256
        case sizeBytes = "size_bytes"
    }
}

public struct PS5NexusCommandLimits: Codable, Equatable, Sendable {
    public let timeoutMS: Int
    public let memoryBytes: UInt64
    public let addressSpaceBytes: UInt64
    public let processes: Int
    public let cpuSeconds: Int
    public let scratchBytes: UInt64
    public let outputBytes: Int
    enum CodingKeys: String, CodingKey {
        case processes
        case timeoutMS = "timeout_ms", memoryBytes = "memory_bytes"
        case addressSpaceBytes = "address_space_bytes", cpuSeconds = "cpu_seconds"
        case scratchBytes = "scratch_bytes", outputBytes = "output_bytes"
    }
    var valid: Bool {
        (1...30_000).contains(timeoutMS) &&
        ((UInt64(16) << 20)...(UInt64(512) << 20)).contains(memoryBytes) &&
        addressSpaceBytes >= memoryBytes && addressSpaceBytes <= (UInt64(16) << 30) &&
        (1...32).contains(processes) && (1...10).contains(cpuSeconds) &&
        (UInt64(4096)...(UInt64(16) << 20)).contains(scratchBytes) &&
        (1...65_536).contains(outputBytes) && memoryBytes % 4096 == 0
    }
}

public struct PS5NexusCommandInvocation: Codable, Equatable, Sendable {
    public let executable: String
    public let arguments: [String]
    public let limits: PS5NexusCommandLimits
    var valid: Bool {
        executable.hasPrefix("/") && executable.utf8.count <= 4096 &&
        !executable.contains("\0") && !executable.contains("\n") && !executable.contains("\r") &&
        executable.dropFirst().split(separator: "/", omittingEmptySubsequences: false).allSatisfy { !$0.isEmpty && $0 != "." && $0 != ".." } &&
        arguments.count <= 64 && arguments.reduce(0) { $0 + $1.utf8.count } <= 8192 &&
        arguments.allSatisfy { !$0.contains("\0") } && limits.valid
    }
}

public struct PS5NexusCommandProfile: Codable, Equatable, Identifiable, Sendable {
    public let id: String
    public let version: String
    public let invocation: PS5NexusCommandInvocation
    var valid: Bool {
        id.range(of: "^[a-z][a-z0-9_-]{0,31}$", options: .regularExpression) == id.startIndex..<id.endIndex &&
        PS5NexusPatchValidation.hex(version, count: 64) && invocation.valid
    }
}

public struct PS5NexusCommandProposal: Codable, Equatable, Sendable {
    public let kind: String
    public let host: String
    public let workspaceID: String
    public let workspaceGeneration: String
    public let snapshotID: String
    public let profileID: String
    public let profileVersion: String
    public let inputDigest: String
    public let inputs: [PS5NexusCommandInput]
    public let expiresAt: Double
    public let invocation: PS5NexusCommandInvocation
    enum CodingKeys: String, CodingKey {
        case kind, host, inputs, invocation
        case workspaceID = "workspace_id", workspaceGeneration = "workspace_generation"
        case snapshotID = "snapshot_id", profileID = "profile_id", profileVersion = "profile_version"
        case inputDigest = "input_digest", expiresAt = "expires_at"
    }
    func valid(host: PS5NexusHost, workspaceID: String) -> Bool {
        let strings = inputs.map(\.path)
        return kind == "command" && self.host == host.rawValue && self.workspaceID == workspaceID &&
        PS5NexusPatchValidation.hex(workspaceGeneration, count: 64) &&
        PS5NexusPatchValidation.hex(snapshotID, count: 32) &&
        profileID.range(of: "^[a-z][a-z0-9_-]{0,31}$", options: .regularExpression) == profileID.startIndex..<profileID.endIndex &&
        PS5NexusPatchValidation.hex(profileVersion, count: 64) &&
        PS5NexusPatchValidation.hex(inputDigest, count: 64) && inputs.count <= 128 &&
        inputs.reduce(0) { $0 + $1.sizeBytes } <= 1 << 20 &&
        strings == strings.sorted() && Set(strings).count == strings.count &&
        inputs.allSatisfy { PS5NexusWorkspaceClient.validRelativePath($0.path) &&
            $0.path.utf8.count <= 512 && $0.path.split(separator: "/").count <= 12 &&
            !$0.path.split(separator: "/").contains(where: { $0.hasPrefix(".") || $0.utf8.count > 255 }) &&
            (0...65_536).contains($0.sizeBytes) && PS5NexusPatchValidation.hex($0.sha256, count: 64) } &&
        inputDigest == PS5NexusCommandBinding.manifest(inputs) &&
        expiresAt.isFinite && expiresAt > 0 && expiresAt <= Double(Int64.max) &&
        expiresAt.rounded(.towardZero) == expiresAt && invocation.valid
    }

    var digest: String {
        let q: (String) -> String = { PS5NexusCommandBinding.quote($0) }
        let limit = invocation.limits
        let bounds = "{\"address_space_bytes\":\(limit.addressSpaceBytes),\"cpu_seconds\":\(limit.cpuSeconds),\"memory_bytes\":\(limit.memoryBytes),\"output_bytes\":\(limit.outputBytes),\"processes\":\(limit.processes),\"scratch_bytes\":\(limit.scratchBytes),\"timeout_ms\":\(limit.timeoutMS)}"
        let arguments = "[" + invocation.arguments.map { q($0) }.joined(separator: ",") + "]"
        let invocationJSON = "{\"arguments\":\(arguments),\"executable\":\(q(invocation.executable)),\"limits\":\(bounds)}"
        let manifest = "[" + inputs.map {
            "{\"path\":\(q($0.path)),\"sha256\":\(q($0.sha256)),\"size_bytes\":\($0.sizeBytes)}"
        }.joined(separator: ",") + "]"
        let json = "{\"expires_at\":\(Int64(expiresAt)),\"host\":\(q(host)),\"input_digest\":\(q(inputDigest)),\"inputs\":\(manifest),\"invocation\":\(invocationJSON),\"kind\":\(q(kind)),\"profile_id\":\(q(profileID)),\"profile_version\":\(q(profileVersion)),\"snapshot_id\":\(q(snapshotID)),\"workspace_generation\":\(q(workspaceGeneration)),\"workspace_id\":\(q(workspaceID))}"
        return PS5NexusCommandBinding.digest(json)
    }
}

public struct PS5NexusCommandReceiptResult: Codable, Equatable, Sendable {
    public let profileID: String
    public let profileVersion: String
    public let inputDigest: String
    public let workspaceGeneration: String
    public let snapshotID: String
    public let stdout: String
    public let stderr: String
    public let exitCode: Int
    public let truncated: Bool
    public let timedOut: Bool
    public let cancelled: Bool
    enum CodingKeys: String, CodingKey {
        case stdout, stderr, truncated, cancelled
        case exitCode = "exit_code", timedOut = "timed_out"
        case profileID = "profile_id", profileVersion = "profile_version"
        case inputDigest = "input_digest", workspaceGeneration = "workspace_generation"
        case snapshotID = "snapshot_id"
    }
}

public struct PS5NexusCommandReceiptRequest: Codable, Equatable, Sendable {
    public let host: String
    public let workspaceID: String
    public let workspaceGeneration: String
    public let owner: String
    public let approvalID: String
    public let digest: String
    public let operationID: String
    public let snapshotID: String
    public let profileID: String
    public let profileVersion: String
    public let inputDigest: String
    public let expiresAt: Int64
    enum CodingKeys: String, CodingKey {
        case host, owner, digest
        case workspaceID = "workspace_id", workspaceGeneration = "workspace_generation"
        case approvalID = "approval_id", operationID = "operation_id"
        case snapshotID = "snapshot_id", profileID = "profile_id"
        case profileVersion = "profile_version", inputDigest = "input_digest"
        case expiresAt = "expires_at"
    }
}

public struct PS5NexusCommandReceipt: Codable, Equatable, Sendable {
    public let request: PS5NexusCommandReceiptRequest
    public let status: String
    public let result: PS5NexusCommandReceiptResult?
    public let failure: String?
}

public struct PS5NexusCommandExecution: Codable, Equatable, Sendable {
    public let operationID: String
    public let phase: String
    public let receipt: PS5NexusCommandReceipt?
    public let cancelRequested: Bool?
    enum CodingKeys: String, CodingKey {
        case phase, receipt
        case operationID = "operation_id", cancelRequested = "cancel_requested"
    }
    func valid(record: PS5NexusCommandRecord) -> Bool {
        guard PS5NexusPatchValidation.hex(operationID, count: 32),
              ["prepared", "dispatching", "uncertain", "completed", "interrupted"].contains(phase)
        else { return false }
        guard let receipt else { return !["completed", "interrupted"].contains(phase) }
        let binding = receipt.request
        let p = record.proposal
        guard phase == receipt.status,
              ["completed", "interrupted"].contains(phase),
              binding.host == p.host, binding.workspaceID == p.workspaceID,
              binding.workspaceGeneration == p.workspaceGeneration,
              PS5NexusPatchValidation.hex(binding.owner, count: 64),
              binding.approvalID == record.id, binding.digest == record.digest,
              binding.operationID == operationID, binding.snapshotID == p.snapshotID,
              binding.profileID == p.profileID, binding.profileVersion == p.profileVersion,
              binding.inputDigest == p.inputDigest, binding.expiresAt > 0,
              Double(binding.expiresAt) <= record.expiresAt else { return false }
        if phase == "interrupted" {
            return receipt.result == nil && receipt.failure == "exit_unknown"
        }
        guard let result = receipt.result,
              result.profileID == p.profileID && result.profileVersion == p.profileVersion &&
              result.inputDigest == p.inputDigest && result.snapshotID == p.snapshotID &&
              result.workspaceGeneration == p.workspaceGeneration &&
              (-1...255).contains(result.exitCode) &&
              result.stdout.utf8.count + result.stderr.utf8.count <= 65_536 &&
              (receipt.failure == nil || receipt.failure == "execution_failed") &&
              (receipt.failure != nil || (!result.cancelled && !result.timedOut && !result.truncated))
        else { return false }
        return true
    }
}

public struct PS5NexusCommandRecord: Codable, Equatable, Identifiable, Sendable {
    public let id: String
    public let digest: String
    public let proposal: PS5NexusCommandProposal
    public let submissionID: String
    public let origin: String
    public let createdAt: Double
    public let expiresAt: Double
    public let status: String
    public let execution: PS5NexusCommandExecution?
    enum CodingKeys: String, CodingKey {
        case id, digest, proposal, origin, status, execution
        case submissionID = "submission_id", createdAt = "created_at", expiresAt = "expires_at"
    }
    public var canReview: Bool { status == "pending" && expiresAt > Date().timeIntervalSince1970 }
    public var canExecute: Bool { status == "approved" && expiresAt > Date().timeIntervalSince1970 }
    public var canReconcile: Bool { status == "executing" &&
        execution.map { ["prepared", "dispatching", "uncertain"].contains($0.phase) } == true }
    public var canCancel: Bool {
        ((status == "pending" || status == "approved") ||
            (status == "executing" && execution.map { ["dispatching", "uncertain"].contains($0.phase) } == true))
    }
    func valid(host: PS5NexusHost, workspaceID: String) -> Bool {
        PS5NexusPatchValidation.hex(id, count: 32) && PS5NexusPatchValidation.hex(digest, count: 64) &&
        PS5NexusPatchValidation.hex(submissionID, count: 32) &&
        ["manual", "agent"].contains(origin) && ["pending", "approved", "rejected", "executing"].contains(status) &&
        PS5NexusPatchValidation.validTimes(createdAt, expiresAt) &&
        proposal.expiresAt == expiresAt && proposal.valid(host: host, workspaceID: workspaceID) &&
        digest == proposal.digest && (status == "executing") == (execution != nil) &&
        (execution.map { $0.valid(record: self) } ?? true)
    }
}

public struct PS5NexusCommandSummary: Codable, Equatable, Identifiable, Sendable {
    public let id: String
    public let digest: String
    public let origin: String
    public let profileID: String
    public let snapshotID: String
    public let inputDigest: String
    public let createdAt: Double
    public let expiresAt: Double
    public let status: String
    public let executionPhase: String?
    enum CodingKeys: String, CodingKey {
        case id, digest, origin, status
        case profileID = "profile_id", snapshotID = "snapshot_id", inputDigest = "input_digest"
        case createdAt = "created_at", expiresAt = "expires_at", executionPhase = "execution_phase"
    }
    var valid: Bool {
        PS5NexusPatchValidation.hex(id, count: 32) && PS5NexusPatchValidation.hex(digest, count: 64) &&
        PS5NexusPatchValidation.hex(snapshotID, count: 32) && PS5NexusPatchValidation.hex(inputDigest, count: 64) &&
        PS5NexusPatchValidation.validTimes(createdAt, expiresAt) &&
        ["manual", "agent"].contains(origin) && ["pending", "approved", "rejected", "executing"].contains(status)
    }
}

struct PS5NexusCommandEnvelope: Decodable {
    let host: String
    let workspaceID: String
    let executionEnabled: Bool
    let command: PS5NexusCommandRecord?
    let commands: [PS5NexusCommandSummary]?
    let workspaceGeneration: String?
    let profiles: [PS5NexusCommandProfile]?
    enum CodingKeys: String, CodingKey {
        case host, command, commands, profiles
        case workspaceID = "workspace_id", executionEnabled = "execution_enabled"
        case workspaceGeneration = "workspace_generation"
    }
}

public enum PS5NexusCommandDecision: String, Sendable { case approve, reject }
public enum PS5NexusCommandAction: String, Sendable { case execute, reconcile, cancel }

public struct PS5NexusCommandClient: Sendable {
    public init() {}
    private let http = PS5NexusHTTPClient()
    static func isCommandRoute(_ path: String) -> Bool {
        path.range(of: "^/nexus/workspaces/(debian|nixos)/[a-z][a-z0-9_-]{0,31}/commands(/[0-9a-f]{32}(/(decision|execute|reconcile|cancel))?)?$",
                   options: .regularExpression) == path.startIndex..<path.endIndex
    }
    private func path(host: PS5NexusHost, workspaceID: String) throws -> String {
        guard PS5NexusPatchValidation.validScope(host: host.rawValue, workspaceID: workspaceID) else { throw PS5NexusError.invalidResponse }
        return "/nexus/workspaces/\(host.rawValue)/\(workspaceID)/commands"
    }
    public func profiles(endpoint: PS5NexusEndpoint, token: String, host: PS5NexusHost,
                         workspaceID: String, generation: String? = nil) async throws -> [PS5NexusCommandProfile] {
        let result: PS5NexusCommandEnvelope = try await http.send(endpoint: endpoint,
            path: path(host: host, workspaceID: workspaceID) + "/profiles", token: token)
        guard result.host == host.rawValue, result.workspaceID == workspaceID, !result.executionEnabled,
              let actualGeneration = result.workspaceGeneration,
              PS5NexusPatchValidation.hex(actualGeneration, count: 64),
              generation.map({ $0 == actualGeneration }) ?? true,
              let items = result.profiles, items.count <= 32,
              items.allSatisfy(\.valid), Set(items.map(\.id)).count == items.count else {
            throw PS5NexusError.invalidResponse
        }
        return items
    }
    public func list(endpoint: PS5NexusEndpoint, token: String, host: PS5NexusHost, workspaceID: String) async throws -> [PS5NexusCommandSummary] {
        let result: PS5NexusCommandEnvelope = try await http.send(endpoint: endpoint, path: path(host: host, workspaceID: workspaceID), token: token)
        guard result.host == host.rawValue && result.workspaceID == workspaceID && !result.executionEnabled,
              let records = result.commands, records.count <= 100 && records.allSatisfy(\.valid),
              Set(records.map(\.id)).count == records.count else { throw PS5NexusError.invalidResponse }
        return records
    }
    public func detail(endpoint: PS5NexusEndpoint, token: String, host: PS5NexusHost, workspaceID: String, id: String) async throws -> PS5NexusCommandRecord {
        guard PS5NexusPatchValidation.hex(id, count: 32) else { throw PS5NexusError.invalidResponse }
        let response: PS5NexusCommandEnvelope = try await http.send(endpoint: endpoint, path: path(host: host, workspaceID: workspaceID) + "/\(id)", token: token)
        return try Self.verify(response, host: host, workspaceID: workspaceID, id: id, execution: false)
    }
    public func propose(profileID: String, submissionID: String, endpoint: PS5NexusEndpoint, token: String,
                        host: PS5NexusHost, workspaceID: String) async throws -> PS5NexusCommandRecord {
        guard profileID.range(of: "^[a-z][a-z0-9_-]{0,31}$", options: .regularExpression) == profileID.startIndex..<profileID.endIndex,
              PS5NexusPatchValidation.hex(submissionID, count: 32) else { throw PS5NexusError.invalidResponse }
        let body = try JSONEncoder().encode(["profile_id": profileID, "submission_id": submissionID])
        let reply: PS5NexusCommandEnvelope = try await http.send(endpoint: endpoint, path: path(host: host, workspaceID: workspaceID),
                                                                 method: "POST", token: token, body: body)
        guard let record = reply.command, record.submissionID == submissionID, record.proposal.profileID == profileID else { throw PS5NexusError.invalidResponse }
        return try Self.verify(reply, host: host, workspaceID: workspaceID, id: record.id, execution: false)
    }
    public func decide(_ decision: PS5NexusCommandDecision, record: PS5NexusCommandRecord,
                       endpoint: PS5NexusEndpoint, token: String, host: PS5NexusHost, workspaceID: String) async throws -> PS5NexusCommandRecord {
        guard record.valid(host: host, workspaceID: workspaceID) && record.canReview else { throw PS5NexusError.patchReviewConflict }
        let body = try JSONEncoder().encode(["digest":record.digest, "decision":decision.rawValue])
        let response: PS5NexusCommandEnvelope = try await http.send(endpoint: endpoint,
            path: path(host: host, workspaceID: workspaceID) + "/\(record.id)/decision", method: "POST", token: token, body: body)
        let updated = try Self.verify(response, host: host, workspaceID: workspaceID, id: record.id, execution: false)
        guard updated.digest == record.digest && updated.proposal == record.proposal &&
              updated.status == (decision == .approve ? "approved" : "rejected") else { throw PS5NexusError.invalidResponse }
        return updated
    }
    public func action(_ action: PS5NexusCommandAction, record: PS5NexusCommandRecord,
                       endpoint: PS5NexusEndpoint, token: String, host: PS5NexusHost, workspaceID: String) async throws -> PS5NexusCommandRecord {
        guard record.valid(host: host, workspaceID: workspaceID),
              (action == .execute ? record.canExecute : action == .reconcile ? record.canReconcile : record.canCancel) else { throw PS5NexusError.patchReviewConflict }
        let body = try JSONEncoder().encode(["digest":record.digest])
        let response: PS5NexusCommandEnvelope = try await http.send(endpoint: endpoint,
            path: path(host: host, workspaceID: workspaceID) + "/\(record.id)/\(action.rawValue)", method: "POST", token: token, body: body)
        let updated = try Self.verify(response, host: host, workspaceID: workspaceID, id: record.id, execution: true)
        guard updated.digest == record.digest && updated.proposal == record.proposal else { throw PS5NexusError.invalidResponse }
        if action == .cancel {
            guard (updated.status == "rejected" && updated.execution == nil) ||
                  (updated.status == "executing" && updated.execution?.cancelRequested == true) ||
                  (updated.status == "executing" && ["completed", "interrupted"].contains(updated.execution?.phase ?? ""))
            else { throw PS5NexusError.invalidResponse }
        } else {
            guard updated.status == "executing", updated.execution != nil else { throw PS5NexusError.invalidResponse }
        }
        return updated
    }
    static func verify(_ result: PS5NexusCommandEnvelope, host: PS5NexusHost, workspaceID: String,
                       id: String, execution: Bool) throws -> PS5NexusCommandRecord {
        guard result.host == host.rawValue && result.workspaceID == workspaceID && result.executionEnabled == execution,
              let item = result.command, item.id == id, item.valid(host: host, workspaceID: workspaceID) else { throw PS5NexusError.invalidResponse }
        return item
    }
}

import Foundation

/// An opaque Keychain identity marker, never an access token or a preference.
public struct PS5NexusPatchBinding: Codable, Equatable, Sendable {
    public let connectionID: UUID
    public let endpoint: String
    public let identity: UUID
    public let host: PS5NexusHost
    public let workspaceID: String

    public init(connectionID: UUID, endpoint: PS5NexusEndpoint, identity: UUID,
                host: PS5NexusHost, workspaceID: String) {
        self.connectionID = connectionID
        self.endpoint = endpoint.baseURL.absoluteString
        self.identity = identity
        self.host = host
        self.workspaceID = workspaceID
    }

    var storageKey: String {
        PS5NexusPatchProposal.hash("\(connectionID)|\(endpoint)|\(host.rawValue)|\(workspaceID)")
    }
}

public enum PS5NexusPatchDraftError: LocalizedError {
    case invalid, identityChanged, pendingExists
    public var errorDescription: String? {
        switch self {
        case .invalid: "The saved patch request or proposed edit is invalid. Use a relative file path and at most 64 KiB of replacement text."
        case .identityChanged: "This saved request belongs to a different credential session. It cannot be retried with the current sign-in."
        case .pendingExists: "A saved request is still pending. Retry that exact request before starting another proposal."
        }
    }
}

/// Prepared once before sending. Persisting the body preserves exact retry bytes.
public struct PS5NexusPatchDraft: Codable, Equatable, Sendable {
    public let binding: PS5NexusPatchBinding
    public let submissionID: String
    public let path: String
    public let replacement: String
    public let body: Data

    private struct Request: Codable, Equatable {
        let path: String
        let replacement: String
        let submission_id: String
    }

    public init(binding: PS5NexusPatchBinding, path: String, replacement: String) throws {
        self.binding = binding
        self.submissionID = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        self.path = path
        self.replacement = replacement
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        self.body = try encoder.encode(Request(path: path, replacement: replacement, submission_id: submissionID))
        try validate()
    }

    public func validate() throws {
        guard PS5NexusPatchValidation.validScope(host: binding.host.rawValue, workspaceID: binding.workspaceID),
              PS5NexusPatchValidation.validPath(path), replacement.utf8.count <= 65_536,
              !replacement.contains("\0"), PS5NexusPatchValidation.hex(submissionID, count: 32),
              body.count <= 512 * 1_024,
              let request = try? JSONDecoder().decode(Request.self, from: body),
              request.path.utf8.elementsEqual(path.utf8),
              request.replacement.utf8.elementsEqual(replacement.utf8), request.submission_id == submissionID,
              let object = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              Set(object.keys) == ["path", "replacement", "submission_id"] else {
            throw PS5NexusPatchDraftError.invalid
        }
    }

    public func validateResponse(_ record: PS5NexusPatchRecord) throws {
        try validate()
        guard record.valid(host: binding.host, workspaceID: binding.workspaceID),
              record.proposal.path.utf8.elementsEqual(path.utf8),
              record.proposal.replacement.utf8.elementsEqual(replacement.utf8) else {
            throw PS5NexusError.invalidResponse
        }
    }
}

import Foundation

/// Synchronous, serialized access: save must succeed before a caller sends.
/// Missing files are empty; inaccessible, corrupt or differently bound files fail closed.
@MainActor
public struct PS5NexusPatchDraftStore {
    private let directory: URL
    public init(directory: URL) { self.directory = directory }

    private func url(_ binding: PS5NexusPatchBinding) -> URL {
        directory.appendingPathComponent(binding.storageKey + ".json")
    }

    public func load(binding: PS5NexusPatchBinding) throws -> PS5NexusPatchDraft? {
        let data: Data
        do { data = try Data(contentsOf: url(binding)) }
        catch let error as CocoaError where error.code == .fileReadNoSuchFile { return nil }
        let draft = try JSONDecoder().decode(PS5NexusPatchDraft.self, from: data)
        try draft.validate()
        guard draft.binding == binding else { throw PS5NexusPatchDraftError.identityChanged }
        return draft
    }

    public func prepare(binding: PS5NexusPatchBinding, path: String, replacement: String) throws -> PS5NexusPatchDraft {
        guard try load(binding: binding) == nil else { throw PS5NexusPatchDraftError.pendingExists }
        let draft = try PS5NexusPatchDraft(binding: binding, path: path, replacement: replacement)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        try JSONEncoder().encode(draft).write(to: url(binding), options: [.atomic, .completeFileProtection])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url(binding).path)
        return draft
    }

    /// Removal is conditional on the exact saved request and a verified reply.
    public func complete(_ draft: PS5NexusPatchDraft, response: PS5NexusPatchRecord) throws {
        try draft.validateResponse(response)
        guard try load(binding: draft.binding) == draft else { throw PS5NexusPatchDraftError.invalid }
        try FileManager.default.removeItem(at: url(draft.binding))
    }
}

import Foundation

/// An in-memory text edit and the remote file version it was based on.
/// The original size and timestamp stay fixed while `contents` changes so
/// SFTP can reject a save if another writer changed the remote file.
public struct RemoteTextDraft: Identifiable, Equatable, Sendable {
    public let id: UUID
    public let path: String
    public let name: String
    public var contents: String
    public let originalContents: String
    public let originalSize: UInt64
    public let originalModifiedAt: Date?

    public init(id: UUID = UUID(), path: String, name: String, contents: String,
                originalContents: String, originalSize: UInt64,
                originalModifiedAt: Date?) {
        self.id = id
        self.path = path
        self.name = name
        self.contents = contents
        self.originalContents = originalContents
        self.originalSize = originalSize
        self.originalModifiedAt = originalModifiedAt
    }

    public var hasUnsavedChanges: Bool { contents != originalContents }
}

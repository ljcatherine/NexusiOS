import XCTest
@testable import NexusCore

final class RemoteTextDraftTests: XCTestCase {
    func testEditedDraftSnapshotRetainsUnsavedContentsAndConflictBaseline() {
        let originalModifiedAt = Date(timeIntervalSince1970: 1_800_000_000)
        var draft = RemoteTextDraft(path: "/srv/config.txt", name: "config.txt",
            contents: "before", originalContents: "before", originalSize: 6,
            originalModifiedAt: originalModifiedAt)

        XCTAssertFalse(draft.hasUnsavedChanges)
        draft.contents = "edited locally"

        // FilesView stores this value while the editor is dismissed for host-key approval.
        let suspendedDraft = draft
        XCTAssertTrue(suspendedDraft.hasUnsavedChanges)
        XCTAssertEqual(suspendedDraft.contents, "edited locally")
        XCTAssertEqual(suspendedDraft.originalContents, "before")
        XCTAssertEqual(suspendedDraft.originalSize, 6)
        XCTAssertEqual(suspendedDraft.originalModifiedAt, originalModifiedAt)
    }
}

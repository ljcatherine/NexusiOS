import Foundation
import XCTest
@testable import NexusCore

final class PS5NexusApprovalRunTests: XCTestCase {
    func testProposalOptInPersistsWithExactPendingRequest() throws {
        let pending = PS5NexusPendingSubmission(id: String(repeating: "a", count: 32),
            prompt: "Propose a small edit", history: [], subagents: 0,
            autoCompact: true, allowProposals: true)
        XCTAssertTrue(pending.isValid)
        let restored = try JSONDecoder().decode(PS5NexusPendingSubmission.self,
            from: JSONEncoder().encode(pending))
        XCTAssertEqual(restored.allowProposals, true)
        XCTAssertEqual(restored, pending)
        let invalid = PS5NexusPendingSubmission(id: pending.id, prompt: pending.prompt,
            history: [.init(role: "user", content: "Context")], subagents: 0,
            autoCompact: true, compactOnly: true, allowProposals: true)
        XCTAssertFalse(invalid.isValid)
    }

    func testLegacyPendingRequestsDoNotOptIntoProposals() throws {
        let data = Data(#"{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","prompt":"Read only","history":[],"subagents":0,"autoCompact":true}"#.utf8)
        let pending = try JSONDecoder().decode(PS5NexusPendingSubmission.self, from: data)
        XCTAssertNil(pending.allowProposals)
        XCTAssertNil(pending.credentialIdentity)
        XCTAssertTrue(pending.isValid)
    }

    func testSavedRunRetryAndModelContextAreBoundToOriginalCredential() throws {
        let owner = UUID()
        let replacementCredential = UUID()
        let runID = String(repeating: "a", count: 32)
        let scope = String(repeating: "1", count: 64)
        let differentScope = String(repeating: "2", count: 64)
        let history = [PS5NexusOrchestratedMessage(role: "user", content: "private prior context")]
        let pending = PS5NexusPendingSubmission(id: runID, prompt: "private task",
            history: history, subagents: 1, autoCompact: true, allowProposals: true,
            credentialIdentity: owner, scopeFingerprint: scope)
        let saved = PS5NexusOrchestratedConversation(contextHistory: history,
            pendingPrompt: pending.prompt, pendingSubmission: pending, credentialIdentity: owner,
            scopeFingerprint: scope)
        XCTAssertTrue(saved.isValid)
        XCTAssertFalse(saved.canSendContext(credential: owner, scope: scope), "pending task cannot be overwritten")
        XCTAssertFalse(saved.canSendContext(credential: replacementCredential, scope: scope))
        XCTAssertTrue(saved.canReadSavedRun(runID: runID, scope: scope))
        XCTAssertFalse(saved.canReadSavedRun(runID: runID, scope: differentScope))
        XCTAssertTrue(saved.canResume(runID: runID, credential: owner, scope: scope))
        XCTAssertFalse(saved.canResume(runID: runID, credential: owner, scope: differentScope))
        XCTAssertFalse(saved.canResume(runID: runID, credential: replacementCredential, scope: scope))
        XCTAssertFalse(saved.canResume(runID: String(repeating: "b", count: 32), credential: owner, scope: scope))
        let restored = try JSONDecoder().decode(PS5NexusOrchestratedConversation.self,
            from: JSONEncoder().encode(saved))
        XCTAssertEqual(restored, saved)
        XCTAssertFalse(restored.canResume(runID: runID, credential: replacementCredential, scope: scope))

        var completed = saved
        completed.pendingPrompt = nil
        completed.pendingSubmission = nil
        XCTAssertTrue(completed.canSendContext(credential: owner, scope: scope))
        XCTAssertFalse(completed.canSendContext(credential: replacementCredential, scope: scope))
        XCTAssertFalse(completed.canSendContext(credential: owner, scope: differentScope))

        // Credential changes must never silently ship old context, but a user
        // can explicitly reset it without deleting the on-device transcript.
        var reset = saved
        reset.pendingPrompt = nil
        reset.pendingSubmission = nil
        reset.contextHistory = []
        reset.credentialIdentity = nil
        reset.scopeFingerprint = nil
        XCTAssertTrue(reset.canSendContext(credential: replacementCredential, scope: differentScope))
        XCTAssertFalse(reset.canResume(runID: runID, credential: owner, scope: scope))
    }

    func testLegacySavedRunNeverAutomaticallyRepostsUnverifiedRequest() throws {
        let runID = String(repeating: "a", count: 32)
        let old = PS5NexusPendingSubmission(id: runID, prompt: "old request",
            history: [], subagents: 0, autoCompact: true)
        let saved = PS5NexusOrchestratedConversation(pendingPrompt: old.prompt,
            pendingSubmission: old)
        let current = UUID()
        let scope = String(repeating: "1", count: 64)
        XCTAssertTrue(saved.isValid)
        XCTAssertFalse(saved.canReadSavedRun(runID: runID, scope: scope))
        XCTAssertFalse(saved.canResume(runID: runID, credential: current, scope: scope))
        let historical = PS5NexusOrchestratedConversation(contextHistory: [
            PS5NexusOrchestratedMessage(role: "assistant", content: "legacy secret")])
        XCTAssertTrue(historical.isValid)
        XCTAssertFalse(historical.canSendContext(credential: current, scope: scope))

        let mismatched = PS5NexusOrchestratedConversation(pendingPrompt: old.prompt,
            pendingSubmission: PS5NexusPendingSubmission(id: runID, prompt: old.prompt,
                history: [], subagents: 0, autoCompact: true, credentialIdentity: current),
            credentialIdentity: UUID())
        XCTAssertFalse(mismatched.isValid)
    }

    func testWaitingRunExposesOnlyOpaqueApprovalReference() throws {
        let data = Data(#"{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","status":"waiting_for_approval","phase":"waiting for patch review","subagents":[],"approval_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","approval_kind":"patch"}"#.utf8)
        let progress = try JSONDecoder().decode(PS5NexusRunProgress.self, from: data)
        XCTAssertEqual(progress.status, "waiting_for_approval")
        XCTAssertEqual(progress.approvalID, String(repeating: "b", count: 32))
        XCTAssertEqual(progress.approvalKind, .patch)
        XCTAssertNil(progress.result)
    }
    func testCommandCheckpointRoutesSeparatelyAndUnknownTypesFailClosed() throws {
        let base = #"{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","status":"waiting_for_approval","phase":"waiting for approved command execution","subagents":[],"approval_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb""#
        let command = try JSONDecoder().decode(PS5NexusRunProgress.self,
            from: Data((base + #", "approval_kind":"command"}"#).utf8))
        XCTAssertEqual(command.approvalKind, .command)
        let legacy = try JSONDecoder().decode(PS5NexusRunProgress.self,
            from: Data((base + "}").utf8))
        XCTAssertNil(legacy.approvalKind)
        XCTAssertThrowsError(try JSONDecoder().decode(PS5NexusRunProgress.self,
            from: Data((base + #", "approval_kind":"shell"}"#).utf8)))
    }
    func testRejectedProposalActivityDoesNotClaimAnEdit() throws {
        let data = Data(#"{"tool":"propose_patch","path":"src/main.py","result_count":1,"status":"rejected","changes_applied":false}"#.utf8)
        let event = try JSONDecoder().decode(PS5NexusWorkspaceToolEvent.self, from: data)
        XCTAssertEqual(event.status, "rejected")
        XCTAssertEqual(event.changesApplied, false)
    }

}

import Foundation
import XCTest
@testable import NexusCore

final class PS5NexusPatchModelTests: XCTestCase {
    private func proposal() -> PS5NexusPatchProposal {
        PS5NexusPatchProposal(host: "debian", workspaceID: "code", path: "src/main.py",
            baseSHA256: "f54a744a4165c15c0449e002a65472c2a8b3fa155edad995d698e2ed1304a020",
            original: "print(\"café\")\n\t# / 🐈\u{2028}\u{1}", replacement: "print(\"done\")\n")
    }

    func testSnapshotDigestMatchesPythonWithUnicodeAndEscapes() throws {
        let value = proposal()
        XCTAssertTrue(value.valid)
        // Produced independently with Python hashlib/json canonical serialization.
        XCTAssertEqual(value.digest, "b2473f436ad720916c0811b623e16aa85ede919af8a1ff6d677cb340df3689fe")
        XCTAssertEqual(try JSONDecoder().decode(PS5NexusPatchProposal.self,
            from: JSONEncoder().encode(value)), value)
    }

    func testOnlyExactSnapshotAndScopeCanBeReviewed() {
        let value = proposal()
        let now = Date().timeIntervalSince1970
        func record(digest: String, expires: Double = now + 900, status: String = "pending") -> PS5NexusPatchRecord {
            PS5NexusPatchRecord(id: String(repeating: "a", count: 32), digest: digest,
                proposal: value, createdAt: now - 1, expiresAt: expires, status: status)
        }
        XCTAssertTrue(record(digest: value.digest).valid(host: .debian, workspaceID: "code"))
        XCTAssertFalse(record(digest: value.digest).valid(host: .nixos, workspaceID: "code"))
        XCTAssertFalse(record(digest: value.digest).valid(host: .debian, workspaceID: "other"))
        XCTAssertFalse(record(digest: String(repeating: "b", count: 64)).valid(host: .debian, workspaceID: "code"))
        XCTAssertFalse(record(digest: value.digest, expires: .infinity).valid(host: .debian, workspaceID: "code"))
        XCTAssertFalse(record(digest: value.digest, expires: now - 0.5).canReview)
        XCTAssertFalse(record(digest: value.digest, status: "approved").canReview)
        XCTAssertFalse(record(digest: value.digest, status: "rejected").canReview)
    }

    func testForgedBaselineAndOversizedReplacementAreRejected() {
        let value = proposal()
        let forged = PS5NexusPatchProposal(host: value.host, workspaceID: value.workspaceID,
            path: value.path, baseSHA256: value.baseSHA256, original: "different", replacement: value.replacement)
        XCTAssertFalse(forged.valid)
        let huge = PS5NexusPatchProposal(host: value.host, workspaceID: value.workspaceID,
            path: value.path, baseSHA256: value.baseSHA256, original: value.original,
            replacement: String(repeating: "é", count: 32_769))
        XCTAssertFalse(huge.valid)
        for path in ["", "/main.py", "../main.py", ".env", "a//b", "a\\b", "a\nb"] {
            XCTAssertFalse(PS5NexusPatchValidation.validPath(path), path)
        }
    }

    func testManagedGenerationIsPartOfTheExactCanonicalDigest() throws {
        var value = proposal()
        value.workspaceGeneration = String(repeating: "c", count: 64)
        XCTAssertTrue(value.valid)
        XCTAssertEqual(value.digest, "95a60c5712fa4b4e806bec2a722e27ebdab2a7ad97ec6a869f5567dd7542ed7c")
        let restored = try JSONDecoder().decode(PS5NexusPatchProposal.self, from: JSONEncoder().encode(value))
        XCTAssertEqual(restored.workspaceGeneration, value.workspaceGeneration)
        value.workspaceGeneration = "not-a-generation"
        XCTAssertFalse(value.valid)
    }

    func testWritableWorkspaceRequiresExplicitGenerationAndCapability() throws {
        let data = Data(#"{"id":"code","name":"Managed","read_only":false,"generation":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","capabilities":["inventory","read_file","apply_patch"]}"#.utf8)
        var root = try JSONDecoder().decode(PS5NexusWorkspace.self, from: data)
        XCTAssertTrue(root.valid)
        XCTAssertTrue(root.supports(.inventory))
        root.generation = nil
        XCTAssertFalse(root.valid)
        XCTAssertFalse(root.supports(.inventory))
    }

    func testManualApplyRequiresAdvertisedProvenanceAndUnexpiredApproval() {
        var value = proposal()
        value.workspaceGeneration = String(repeating: "c", count: 64)
        let now = Date().timeIntervalSince1970
        var record = PS5NexusPatchRecord(id: String(repeating: "a", count: 32), digest: value.digest,
            proposal: value, createdAt: now - 1, expiresAt: now + 900, status: "approved")
        XCTAssertFalse(record.canApply)
        record.manualExecutionAllowed = true
        XCTAssertTrue(record.canApply)
        XCTAssertTrue(record.valid(host: .debian, workspaceID: "code"))
        record.manualExecutionAllowed = false
        XCTAssertFalse(record.canApply)
        let expired = PS5NexusPatchRecord(id: record.id, digest: value.digest, proposal: value,
            createdAt: now - 900, expiresAt: now - 1, status: "approved", manualExecutionAllowed: true)
        XCTAssertFalse(expired.canApply)
    }

    func testReceiptRecoveryIsAdvertisedOnlyForAnExistingManualOperation() {
        var value = proposal()
        value.workspaceGeneration = String(repeating: "c", count: 64)
        let now = Date().timeIntervalSince1970
        let receipt = PS5NexusPatchExecution(operationID: String(repeating: "b", count: 32),
            phase: "uncertain", resultSHA256: nil, createdAt: now - 10, updatedAt: now)
        var record = PS5NexusPatchRecord(id: String(repeating: "a", count: 32), digest: value.digest,
            proposal: value, createdAt: now - 900, expiresAt: now - 1, status: "executing", execution: receipt)
        XCTAssertFalse(record.canReconcile)
        record.manualExecutionAllowed = true
        XCTAssertTrue(record.canReconcile)
        XCTAssertFalse(record.canApply)
        XCTAssertTrue(record.valid(host: .debian, workspaceID: "code"))
    }

    func testAppliedExecutionMetadataMustMatchReplacementAndConsumedApproval() {
        let p = proposal()
        let now = Date().timeIntervalSince1970
        var record = PS5NexusPatchRecord(id: String(repeating: "a", count: 32), digest: p.digest,
            proposal: p, createdAt: now, expiresAt: now + 900, status: "executing")
        record.execution = PS5NexusPatchExecution(operationID: String(repeating: "b", count: 32),
            phase: "applied", resultSHA256: PS5NexusPatchProposal.hash(p.replacement), createdAt: now, updatedAt: now)
        XCTAssertTrue(record.valid(host: .debian, workspaceID: "code"))
        record.execution = PS5NexusPatchExecution(operationID: String(repeating: "b", count: 32),
            phase: "applied", resultSHA256: String(repeating: "f", count: 64), createdAt: now, updatedAt: now)
        XCTAssertFalse(record.valid(host: .debian, workspaceID: "code"))
    }

}

import Foundation
import XCTest
@testable import NexusCore

final class PS5NexusPatchDraftTests: XCTestCase {
    private func binding(connectionID: UUID = UUID(), identity: UUID = UUID(),
                         endpoint: String = "https://gateway.example/v1", host: PS5NexusHost = .debian,
                         workspaceID: String = "code") throws -> PS5NexusPatchBinding {
        let connection = AIConnection(name: "Gateway", provider: .customOpenAICompatible, baseURL: endpoint)
        return PS5NexusPatchBinding(connectionID: connectionID,
            endpoint: try PS5NexusEndpoint(managementURL: endpoint, connection: connection),
            identity: identity, host: host, workspaceID: workspaceID)
    }

    private func record(path: String = "src/main.py", replacement: String = "new\n",
                        host: String = "debian", root: String = "code", badBase: Bool = false,
                        badDigest: Bool = false) -> PS5NexusPatchRecord {
        let proposal = PS5NexusPatchProposal(host: host, workspaceID: root, path: path,
            baseSHA256: badBase ? String(repeating: "0", count: 64) : PS5NexusPatchProposal.hash("old\n"),
            original: "old\n", replacement: replacement)
        return PS5NexusPatchRecord(id: String(repeating: "a", count: 32),
            digest: badDigest ? String(repeating: "0", count: 64) : proposal.digest,
            proposal: proposal, createdAt: 1_700_000_000, expiresAt: 1_700_000_900, status: "pending")
    }

    @MainActor
    func testRestartRetainsExactRequestAndCannotReplacePendingContents() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let scope = try binding()
        let store = PS5NexusPatchDraftStore(directory: directory)
        XCTAssertNil(try store.load(binding: scope))
        let prepared = try store.prepare(binding: scope, path: "src/main.py", replacement: "new\n")
        let restored = try XCTUnwrap(PS5NexusPatchDraftStore(directory: directory).load(binding: scope))
        let file = directory.appendingPathComponent(scope.storageKey + ".json")
        let attributes = try FileManager.default.attributesOfItem(atPath: file.path)
        XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o600)
        XCTAssertEqual(restored.body, prepared.body)
        XCTAssertEqual(restored.submissionID, prepared.submissionID)
        let request = try XCTUnwrap(JSONSerialization.jsonObject(with: restored.body) as? [String: String])
        XCTAssertEqual(request, ["path": "src/main.py", "replacement": "new\n", "submission_id": prepared.submissionID])
        XCTAssertThrowsError(try store.prepare(binding: scope, path: "other.py", replacement: "changed"))
        XCTAssertEqual(try store.load(binding: scope)?.body, prepared.body)
        XCTAssertThrowsError(try store.complete(restored, response: record(replacement: "wrong")))
        XCTAssertNotNil(try store.load(binding: scope))
        try store.complete(restored, response: record())
        XCTAssertNil(try store.load(binding: scope))
    }

    @MainActor
    func testIdentityChangeFailsClosedAndOtherScopesDoNotRecoverRequest() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let scope = try binding()
        let store = PS5NexusPatchDraftStore(directory: directory)
        let saved = try store.prepare(binding: scope, path: "src/main.py", replacement: "new\n")
        let changedIdentity = try binding(connectionID: scope.connectionID)
        XCTAssertThrowsError(try store.load(binding: changedIdentity))
        XCTAssertThrowsError(try store.prepare(binding: changedIdentity, path: "new.py", replacement: "new"))
        for other in [try binding(identity: scope.identity),
                      try binding(connectionID: scope.connectionID, identity: scope.identity, endpoint: "https://other.example/v1"),
                      try binding(connectionID: scope.connectionID, identity: scope.identity, host: .nixos),
                      try binding(connectionID: scope.connectionID, identity: scope.identity, workspaceID: "other")] {
            XCTAssertNil(try store.load(binding: other))
        }
        XCTAssertEqual(try store.load(binding: scope), saved)
    }

    @MainActor
    func testCorruptAndUnavailableStorageNeverBecomeEmptyDrafts() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let scope = try binding()
        let store = PS5NexusPatchDraftStore(directory: directory)
        _ = try store.prepare(binding: scope, path: "src/main.py", replacement: "new\n")
        let file = directory.appendingPathComponent(scope.storageKey + ".json")
        try Data("broken".utf8).write(to: file)
        XCTAssertThrowsError(try store.load(binding: scope))
        XCTAssertThrowsError(try store.prepare(binding: scope, path: "x.py", replacement: "x"))
        let blocked = PS5NexusPatchDraftStore(directory: file)
        XCTAssertThrowsError(try blocked.prepare(binding: scope, path: "x.py", replacement: "x"))
    }

    func testInputBoundsAndEmptyReplacement() throws {
        let scope = try binding()
        XCTAssertNoThrow(try PS5NexusPatchDraft(binding: scope, path: "src/main.py", replacement: ""))
        XCTAssertNoThrow(try PS5NexusPatchDraft(binding: scope, path: "src/main.py", replacement: String(repeating: "é", count: 32_768)))
        for text in ["\0", String(repeating: "é", count: 32_769)] {
            XCTAssertThrowsError(try PS5NexusPatchDraft(binding: scope, path: "src/main.py", replacement: text))
        }
        for path in ["", "/main.py", "../main.py", "a//b", "a\\b", "a\nb", ".env"] {
            XCTAssertThrowsError(try PS5NexusPatchDraft(binding: scope, path: path, replacement: "x"), path)
        }
    }

    func testResponseMustMatchScopeBytesBaselineAndCanonicalDigest() throws {
        let draft = try PS5NexusPatchDraft(binding: binding(), path: "src/main.py", replacement: "new\n")
        XCTAssertNoThrow(try draft.validateResponse(record()))
        for response in [record(path: "other.py"), record(replacement: "other"), record(host: "nixos"),
                         record(root: "other"), record(badBase: true), record(badDigest: true)] {
            XCTAssertThrowsError(try draft.validateResponse(response))
        }
        let unicode = try PS5NexusPatchDraft(binding: binding(), path: "src/main.py", replacement: "é")
        XCTAssertThrowsError(try unicode.validateResponse(record(replacement: "e\u{301}")))
    }

    func testEnvelopeMustRemainReviewOnlyAndMatchRequestedScope() throws {
        let draft = try PS5NexusPatchDraft(binding: binding(), path: "src/main.py", replacement: "new\n")
        func envelope(host: String = "debian", root: String = "code", execution: Bool = false) throws -> PS5NexusPatchEnvelope {
            let patch = try JSONSerialization.jsonObject(with: JSONEncoder().encode(record()))
            let data = try JSONSerialization.data(withJSONObject: ["host": host, "workspace_id": root,
                "execution_enabled": execution, "patch": patch])
            return try JSONDecoder().decode(PS5NexusPatchEnvelope.self, from: data)
        }
        XCTAssertNoThrow(try PS5NexusPatchClient.validatedProposal(envelope(), draft: draft))
        XCTAssertThrowsError(try PS5NexusPatchClient.validatedProposal(envelope(execution: true), draft: draft))
        XCTAssertThrowsError(try PS5NexusPatchClient.validatedProposal(envelope(host: "nixos"), draft: draft))
        XCTAssertThrowsError(try PS5NexusPatchClient.validatedProposal(envelope(root: "other"), draft: draft))
    }

    func testTamperedStoredBodyIsRejected() throws {
        let draft = try PS5NexusPatchDraft(binding: binding(), path: "src/main.py", replacement: "new\n")
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(draft)) as? [String: Any])
        object["body"] = Data("{\"path\":\"different.py\"}".utf8).base64EncodedString()
        let decoded = try JSONDecoder().decode(PS5NexusPatchDraft.self, from: JSONSerialization.data(withJSONObject: object))
        XCTAssertThrowsError(try decoded.validate())
    }

    func testClientRefusesDifferentIdentityOrEndpointBeforeSending() async throws {
        let scope = try binding()
        let draft = try PS5NexusPatchDraft(binding: scope, path: "src/main.py", replacement: "new\n")
        let connection = AIConnection(name: "Gateway", provider: .customOpenAICompatible,
            baseURL: "https://gateway.example/v1")
        let endpoint = try PS5NexusEndpoint(managementURL: connection.baseURL, connection: connection)
        let otherEndpoint = try PS5NexusEndpoint(managementURL: "https://other.example/v1", connection: connection)
        for (currentScope, currentEndpoint) in [(try binding(connectionID: scope.connectionID), endpoint),
                                               (scope, otherEndpoint)] {
            do {
                _ = try await PS5NexusPatchClient().propose(draft, binding: currentScope,
                    endpoint: currentEndpoint, token: "")
                XCTFail("A mismatched identity or endpoint must fail before transport")
            } catch PS5NexusPatchDraftError.identityChanged {
                // Expected before token validation or network access.
            } catch { XCTFail("Unexpected error: \(error)") }
        }
    }
}

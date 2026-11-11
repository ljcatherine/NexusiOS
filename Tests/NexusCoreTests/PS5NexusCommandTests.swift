import XCTest
@testable import NexusCore

final class PS5NexusCommandTests: XCTestCase {
    private let expectedDigest = "1fbe086f91243a5ea712e64614245b8644f789f1157ecbd0ab45f278788c2ef8"

    private func proposal() -> PS5NexusCommandProposal {
        let inputs = [
            PS5NexusCommandInput(path: "src/a&b.py", sizeBytes: 4,
                sha256: "d74ff0ee8da3b9806b18c877dbf29bbde50b5bd8e4dad7a3a725000feb82e8f1"),
            PS5NexusCommandInput(path: "src/café.py", sizeBytes: 3,
                sha256: "edd3a863872a04239eb29ad4bc12fc892b3d4ae57cc7e786a3697816f8e141c2")
        ]
        let limits = PS5NexusCommandLimits(timeoutMS: 30_000, memoryBytes: 128 << 20,
            addressSpaceBytes: UInt64(8) << 30, processes: 16, cpuSeconds: 10,
            scratchBytes: 1 << 20, outputBytes: 65_536)
        return PS5NexusCommandProposal(kind: "command", host: "debian", workspaceID: "code",
            workspaceGeneration: String(repeating: "c", count: 64),
            snapshotID: String(repeating: "d", count: 32), profileID: "tests",
            profileVersion: String(repeating: "e", count: 64),
            inputDigest: "c9dc3f66b0e810297961230ea6c869aaae2fa7475b8945202e3d70c7b1b7a8ed",
            inputs: inputs, expiresAt: 1_793_799_999,
            invocation: PS5NexusCommandInvocation(executable: "/usr/bin/python3",
                arguments: ["-m", "unittest", "--unicode=é🧪", "--quote=\"x\""], limits: limits))
    }

    private func record(_ proposal: PS5NexusCommandProposal, status: String = "pending",
                        digest: String? = nil, execution: PS5NexusCommandExecution? = nil) -> PS5NexusCommandRecord {
        PS5NexusCommandRecord(id: String(repeating: "a", count: 32), digest: digest ?? expectedDigest,
            proposal: proposal, submissionID: String(repeating: "b", count: 32), origin: "manual",
            createdAt: 1_793_799_899, expiresAt: proposal.expiresAt, status: status, execution: execution)
    }

    func testGoManifestAndPythonCanonicalProposalDigestAgreeWithUnicodeAndHTMLEscaping() {
        let p = proposal()
        XCTAssertEqual(PS5NexusCommandBinding.manifest(p.inputs), p.inputDigest)
        XCTAssertEqual(p.digest, expectedDigest)
        XCTAssertTrue(p.valid(host: .debian, workspaceID: "code"))
        XCTAssertTrue(record(p).valid(host: .debian, workspaceID: "code"))
        XCTAssertEqual(PS5NexusCommandBinding.quote("<>&é\u{2028}", goHTML: true),
                       "\"\\u003c\\u003e\\u0026é\\u2028\"")
        XCTAssertEqual(PS5NexusCommandBinding.quote("<>&é\u{2028}"), "\"<>&é\u{2028}\"")
    }

    func testUnboundProposalSnapshotInvocationOrDigestCannotBeReviewed() {
        let p = proposal()
        XCTAssertFalse(record(p, digest: String(repeating: "f", count: 64)).valid(host: .debian, workspaceID: "code"))
        XCTAssertFalse(record(p).valid(host: .nixos, workspaceID: "code"))
        let forged = PS5NexusCommandProposal(kind: p.kind, host: p.host, workspaceID: p.workspaceID,
            workspaceGeneration: p.workspaceGeneration, snapshotID: p.snapshotID,
            profileID: p.profileID, profileVersion: p.profileVersion,
            inputDigest: String(repeating: "0", count: 64), inputs: p.inputs,
            expiresAt: p.expiresAt, invocation: p.invocation)
        XCTAssertFalse(forged.valid(host: .debian, workspaceID: "code"))
        let changed = PS5NexusCommandProposal(kind: p.kind, host: p.host, workspaceID: p.workspaceID,
            workspaceGeneration: p.workspaceGeneration, snapshotID: p.snapshotID,
            profileID: p.profileID, profileVersion: p.profileVersion,
            inputDigest: p.inputDigest, inputs: p.inputs,
            expiresAt: p.expiresAt, invocation: PS5NexusCommandInvocation(
                executable: p.invocation.executable,
                arguments: p.invocation.arguments + ["--unapproved"], limits: p.invocation.limits))
        XCTAssertFalse(record(changed).valid(host: .debian, workspaceID: "code"))
        let response = PS5NexusCommandEnvelope(host: "debian", workspaceID: "code",
            executionEnabled: false, command: record(p), commands: nil, workspaceGeneration: nil,
            profiles: nil)
        XCTAssertNoThrow(try PS5NexusCommandClient.verify(response, host: .debian,
            workspaceID: "code", id: String(repeating: "a", count: 32), execution: false))
        XCTAssertThrowsError(try PS5NexusCommandClient.verify(response, host: .debian,
            workspaceID: "code", id: String(repeating: "a", count: 32), execution: true))
    }

    func testTerminalReceiptMustBindOriginalOperationAndResultFlags() {
        let p = proposal()
        let request = PS5NexusCommandReceiptRequest(host: "debian", workspaceID: "code",
            workspaceGeneration: p.workspaceGeneration, owner: String(repeating: "f", count: 64),
            approvalID: String(repeating: "a", count: 32), digest: expectedDigest,
            operationID: String(repeating: "d", count: 32), snapshotID: p.snapshotID,
            profileID: p.profileID, profileVersion: p.profileVersion, inputDigest: p.inputDigest,
            expiresAt: Int64(p.expiresAt))
        let result = PS5NexusCommandReceiptResult(profileID: p.profileID,
            profileVersion: p.profileVersion, inputDigest: p.inputDigest,
            workspaceGeneration: p.workspaceGeneration, snapshotID: p.snapshotID,
            stdout: "", stderr: "", exitCode: -1, truncated: false, timedOut: false, cancelled: true)
        let receipt = PS5NexusCommandReceipt(request: request, status: "completed",
            result: result, failure: "execution_failed")
        let execution = PS5NexusCommandExecution(operationID: request.operationID,
            phase: "completed", receipt: receipt, cancelRequested: true)
        XCTAssertTrue(record(p, status: "executing", execution: execution).valid(host: .debian, workspaceID: "code"))
        let wrong = PS5NexusCommandReceiptRequest(host: request.host, workspaceID: request.workspaceID,
            workspaceGeneration: request.workspaceGeneration, owner: request.owner,
            approvalID: String(repeating: "0", count: 32), digest: request.digest,
            operationID: request.operationID, snapshotID: request.snapshotID,
            profileID: request.profileID, profileVersion: request.profileVersion,
            inputDigest: request.inputDigest, expiresAt: request.expiresAt)
        let forged = PS5NexusCommandExecution(operationID: request.operationID,
            phase: "completed", receipt: PS5NexusCommandReceipt(request: wrong,
            status: "completed", result: result, failure: "execution_failed"), cancelRequested: true)
        XCTAssertFalse(record(p, status: "executing", execution: forged).valid(host: .debian, workspaceID: "code"))
        let unknown = PS5NexusCommandExecution(operationID: request.operationID,
            phase: "interrupted", receipt: PS5NexusCommandReceipt(request: request,
                status: "interrupted", result: nil, failure: "exit_unknown"), cancelRequested: true)
        XCTAssertTrue(record(p, status: "executing", execution: unknown).valid(host: .debian, workspaceID: "code"))
        XCTAssertFalse(record(p, status: "approved", execution: execution).valid(host: .debian, workspaceID: "code"))
    }

    func testCommandRoutesAreExactAndSeparateFromPatchPaths() {
        let root = "/nexus/workspaces/debian/code/commands"
        XCTAssertTrue(PS5NexusCommandClient.isCommandRoute(root))
        for action in ["decision", "execute", "reconcile", "cancel"] {
            XCTAssertTrue(PS5NexusCommandClient.isCommandRoute(root + "/" + String(repeating: "a", count: 32) + "/" + action))
        }
        for bad in [root+"/shell", root+"?host=nixos", root+"/"+String(repeating: "g", count: 32),
                    "/nexus/workspaces/other/code/commands", "/nexus/workspaces/debian/code/patches"] {
            XCTAssertFalse(PS5NexusCommandClient.isCommandRoute(bad))
        }
    }

    func testTypedOwnerOnlyProfileInventoryContainsOnlyVersionedFixedExecutables() throws {
        let p = proposal()
        let profile = PS5NexusCommandProfile(id: p.profileID, version: p.profileVersion,
            invocation: p.invocation)
        XCTAssertTrue(profile.valid)
        let raw = """
        {"host":"debian","workspace_id":"code","execution_enabled":false,
         "workspace_generation":"\(p.workspaceGeneration)","profiles":[
         {"id":"tests","version":"\(p.profileVersion)","invocation":{
          "executable":"/usr/bin/python3","arguments":["-m","unittest"],
          "limits":{"timeout_ms":30000,"memory_bytes":134217728,
                    "address_space_bytes":8589934592,"processes":16,"cpu_seconds":10,
                    "scratch_bytes":1048576,"output_bytes":65536}}}]}
        """
        let decoded = try JSONDecoder().decode(PS5NexusCommandEnvelope.self, from: Data(raw.utf8))
        XCTAssertEqual(decoded.host, "debian")
        XCTAssertEqual(decoded.workspaceGeneration, p.workspaceGeneration)
        XCTAssertEqual(decoded.profiles?.map(\.id), ["tests"])
        XCTAssertTrue(decoded.profiles?.allSatisfy(\.valid) == true)
        let invalid = PS5NexusCommandProfile(id: "../shell", version: profile.version,
            invocation: profile.invocation)
        XCTAssertFalse(invalid.valid)
    }
}

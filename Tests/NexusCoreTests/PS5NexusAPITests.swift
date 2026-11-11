import Foundation
import XCTest
@testable import NexusCore

final class PS5NexusAPITests: XCTestCase {
    func testWorkspaceGitCapabilitiesAreExplicitAndLegacyDiscoveryRemainsReadOnly() throws {
        let legacy = try JSONDecoder().decode(PS5NexusWorkspace.self,
            from: Data(#"{"id":"code","name":"Code"}"#.utf8))
        XCTAssertTrue(legacy.valid)
        XCTAssertTrue(legacy.supports(.inventory))
        XCTAssertFalse(legacy.supports(.gitStatus))
        let capable = try JSONDecoder().decode(PS5NexusWorkspace.self,
            from: Data(#"{"id":"code","name":"Code","read_only":true,"capabilities":["inventory","git_status","git_diff","git_diff_staged"]}"#.utf8))
        XCTAssertTrue(capable.valid)
        XCTAssertTrue(capable.supports(.gitStatus))
        XCTAssertTrue(capable.supports(.gitDiffStaged))
        XCTAssertFalse(capable.supports(.findText))
        var unsupported = capable
        unsupported.capabilities = ["shell"]
        XCTAssertFalse(unsupported.valid)
        unsupported = capable
        unsupported.readOnly = false
        XCTAssertFalse(unsupported.valid)
        XCTAssertFalse(unsupported.supports(.gitStatus))
    }

    func testLongTaskPromptPersistsWithinByteLimit() {
        let prompt = String(repeating: "é", count: 12_000)
        let submission = PS5NexusPendingSubmission(id: String(repeating: "a", count: 32),
            prompt: prompt, history: [], subagents: 0, autoCompact: true)
        XCTAssertTrue(submission.isValid)
        XCTAssertTrue(PS5NexusOrchestratedTurn(prompt: prompt, status: "failed").isValid)
        XCTAssertFalse(PS5NexusOrchestratedTurn(prompt: String(repeating: "é", count: 24_577), status: "failed").isValid)
    }

    func testManualCompactionSubmissionSurvivesRecovery() throws {
        let history = [PS5NexusOrchestratedMessage(role: "user", content: "Keep this")]
        let pending = PS5NexusPendingSubmission(id: String(repeating: "a", count: 32),
            prompt: "Compact model context", history: history, subagents: 0,
            autoCompact: true, compactOnly: true)
        XCTAssertTrue(pending.isValid)
        let restored = try JSONDecoder().decode(PS5NexusPendingSubmission.self, from: JSONEncoder().encode(pending))
        XCTAssertEqual(restored.compactOnly, true)
        let invalid = PS5NexusPendingSubmission(id: String(repeating: "a", count: 32),
            prompt: "Compact model context", history: [], subagents: 0,
            autoCompact: true, compactOnly: true)
        XCTAssertFalse(invalid.isValid)
    }
    func testTaskFailureDescriptionsDoNotEchoServerText() {
        XCTAssertTrue(PS5NexusError.taskFailureDescription(phase: "context limit exceeded").contains("context"))
        XCTAssertTrue(PS5NexusError.taskFailureDescription(phase: "upstream unavailable").contains("unavailable"))
        XCTAssertTrue(PS5NexusError.taskFailureDescription(phase: "authorization revoked").contains("revoked"))
        XCTAssertFalse(PS5NexusError.taskFailureDescription(phase: "untrusted private detail").contains("untrusted"))
    }

    private let connection = AIConnection(
        name: "PS5 API", provider: .ps5lmPlus,
        baseURL: "http://192.168.1.50:8081/v1")

    func testManagementErrorsDistinguishPermissionAndRunRecovery() {
        let run = "/nexus/agent-runs/0123456789abcdef0123456789abcdef"
        XCTAssertEqual(PS5NexusHTTPClient.httpFailure(401, method: "GET", path: run), .unauthorized)
        XCTAssertEqual(PS5NexusHTTPClient.httpFailure(403, method: "GET", path: run), .forbidden)
        XCTAssertEqual(PS5NexusHTTPClient.httpFailure(404, method: "GET", path: run), .runNotFound)
        XCTAssertEqual(PS5NexusHTTPClient.httpFailure(404, method: "GET", path: "/nexus/models"), .unavailable)
        XCTAssertEqual(PS5NexusHTTPClient.httpFailure(410, method: "POST", path: "/nexus/agent-runs"), .runExpired)
    }

    func testManagementEndpointMustBeExplicitAndPrivateForHTTP() throws {
        XCTAssertThrowsError(try PS5NexusEndpoint(managementURL: "", connection: connection))
        XCTAssertThrowsError(try PS5NexusEndpoint(
            managementURL: "http://example.org:8082/v1", connection: connection))
        XCTAssertThrowsError(try PS5NexusEndpoint(
            managementURL: "http://192.168.1.50:8082/v1?token=secret", connection: connection))
        XCTAssertThrowsError(try PS5NexusEndpoint(
            managementURL: "http://alice:password@192.168.1.50:8082/v1", connection: connection))
        XCTAssertThrowsError(try PS5NexusEndpoint(
            managementURL: "http://192.168.1.50:8082/other", connection: connection))
        XCTAssertNoThrow(try PS5NexusEndpoint(
            managementURL: "http://192.168.1.50:8082/v1", connection: connection))
        XCTAssertNoThrow(try PS5NexusEndpoint(
            managementURL: "http://100.64.10.1:8082/v1", connection: connection))
    }

    func testPendingRunScopeChangesWithGatewayAndWorkspaceIdentity() throws {
        let endpoint = try PS5NexusEndpoint(managementURL: "http://192.168.1.50:8081/v1",
            connection: connection, reuseConnectionCredential: true)
        let otherEndpoint = try PS5NexusEndpoint(managementURL: "http://192.168.1.50:8082/v1",
            connection: connection)
        let workspace = try JSONDecoder().decode(PS5NexusWorkspace.self,
            from: Data(#"{"id":"code","name":"Code","generation":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#.utf8))
        XCTAssertTrue(workspace.valid)
        let scope = PS5NexusRunScope.fingerprint(endpoint: endpoint, host: .debian,
            workspace: workspace, path: "src")
        XCTAssertTrue(PS5NexusPatchValidation.hex(scope, count: 64))
        XCTAssertEqual(scope, PS5NexusRunScope.fingerprint(endpoint: endpoint, host: .debian,
            workspace: workspace, path: "src"))
        XCTAssertNotEqual(scope, PS5NexusRunScope.fingerprint(endpoint: otherEndpoint,
            host: .debian, workspace: workspace, path: "src"))
        XCTAssertNotEqual(scope, PS5NexusRunScope.fingerprint(endpoint: endpoint,
            host: .nixos, workspace: workspace, path: "src"))
        XCTAssertNotEqual(scope, PS5NexusRunScope.fingerprint(endpoint: endpoint,
            host: .debian, workspace: workspace, path: "src/other"))
        var changed = workspace
        changed.generation = String(repeating: "b", count: 64)
        XCTAssertNotEqual(scope, PS5NexusRunScope.fingerprint(endpoint: endpoint,
            host: .debian, workspace: changed, path: "src"))
    }

    func testReuseNeverLeaksInferenceKeyToAlternateControllerPort() throws {
        XCTAssertThrowsError(try PS5NexusEndpoint(
            managementURL: "http://192.168.1.50:8082/v1",
            connection: connection, reuseConnectionCredential: true))
        XCTAssertNoThrow(try PS5NexusEndpoint(
            managementURL: "http://192.168.1.50:8081/v1",
            connection: connection, reuseConnectionCredential: true))
        let gateway = AIConnection(name: "Gateway", provider: .customOpenAICompatible,
                                   baseURL: "https://gateway.example/v1")
        XCTAssertNoThrow(try PS5NexusEndpoint(
            managementURL: "https://gateway.example/v1",
            connection: gateway, reuseConnectionCredential: true))
        XCTAssertThrowsError(try PS5NexusEndpoint(
            managementURL: "https://other.example/v1",
            connection: gateway, reuseConnectionCredential: true))
    }

    func testWorkspacePathsAndQueryCannotEscapeScope() throws {
        XCTAssertTrue(PS5NexusWorkspaceClient.validRelativePath(""))
        XCTAssertTrue(PS5NexusWorkspaceClient.validRelativePath("src/main.swift"))
        for value in ["/etc/passwd", "../", "src/../../etc", "a/./b", "a//b", "a\\b", String(repeating: "q", count: 520)] {
            XCTAssertFalse(PS5NexusWorkspaceClient.validRelativePath(value), value)
        }
        let endpoint = try PS5NexusEndpoint(
            managementURL: "https://gateway.example/v1",
            connection: AIConnection(name: "Gateway", provider: .customOpenAICompatible,
                                     baseURL: "https://gateway.example/v1"))
        let query = try endpoint.url(path: "/workspaces/valid_id/files",
                                     query: [URLQueryItem(name: "path", value: "dir/a b.swift"),
                                             URLQueryItem(name: "host", value: "nixos")])
        let items = URLComponents(url: query, resolvingAgainstBaseURL: false)?.queryItems
        XCTAssertEqual(items?.first(where: { $0.name == "path" })?.value, "dir/a b.swift")
        XCTAssertThrowsError(try endpoint.url(path: "/../../admin"))
        XCTAssertThrowsError(try endpoint.url(path: "/workspaces?host=debian"))
    }

    func testModelMetadataComesFromTypedResponseNotFilename() throws {
        let model = try JSONDecoder().decode(PS5NexusModel.self, from: Data(#"{"id":"9f0088aacc224466","label":"misleading-Q4_K_M","drive":"internal","fits":true,"current":true,"file_size_bytes":8589934592,"architecture":"qwen35","quantization_type":18}"#.utf8))
        XCTAssertTrue(model.valid)
        XCTAssertEqual(model.fileSizeBytes, 8_589_934_592)
        XCTAssertEqual(model.architecture, "qwen35")
        XCTAssertEqual(model.quantizationName, "Q6_K")
        let legacy = PS5NexusModel(id: model.id, label: "Q6_K filename only", drive: "usb", fits: false, current: false)
        XCTAssertTrue(legacy.valid)
        XCTAssertNil(legacy.quantizationName)
        XCTAssertNil(legacy.fileSizeBytes)
        XCTAssertEqual(PS5NexusModel(id: model.id, label: "F16", drive: "usb", fits: false, current: false,
                                    quantizationType: 0).quantizationName, "F32")
        XCTAssertEqual(PS5NexusModel(id: model.id, label: "Q6_K", drive: "usb", fits: false, current: false,
                                    quantizationType: 999).quantizationName, "Unknown GGUF type 999")
    }

    func testModelMetadataRejectsMalformedSizesTypesAndArchitecture() throws {
        let base: [String: Any] = ["id": "9f0088aacc224466", "label": "Qwen", "drive": "usb", "fits": false, "current": false]
        for (key, value) in [("file_size_bytes", -1), ("quantization_type", -1),
                             ("quantization_type", 4_294_967_296)] {
            var body = base; body[key] = value
            XCTAssertThrowsError(try JSONDecoder().decode(PS5NexusModel.self,
                from: JSONSerialization.data(withJSONObject: body)))
        }
        let invalid: [(String, Any)] = [("file_size_bytes", 0), ("file_size_bytes", 9_007_199_254_740_992),
                                        ("quantization_type", 1024), ("architecture", "bad\narch"),
                                        ("architecture", String(repeating: "a", count: 65))]
        for (key, value) in invalid {
            var body = base; body[key] = value
            let decoded = try JSONDecoder().decode(PS5NexusModel.self,
                from: JSONSerialization.data(withJSONObject: body))
            XCTAssertFalse(decoded.valid)
        }
    }

    func testCanonicalPS5ControllerModelsAndStatusDecode() throws {
        let list = try JSONDecoder().decode(PS5NexusModelList.self,
            from: Data(#"{"models":[{"id":"9f0088aacc224466","label":"Qwen","drive":"usb","fits":true,"current":false}]}"#.utf8))
        XCTAssertEqual(list.models.count, 1)
        XCTAssertTrue(list.models[0].valid)
        XCTAssertFalse(PS5NexusModel(id: "../path", label: "Unsafe", drive: "usb",
                                      fits: true, current: false).valid)
        let status = try JSONDecoder().decode(PS5NexusStatus.self,
            from: Data(#"{"state":"ready","model_id":"9f0088aacc224466","model":"Qwen","context_size":32768,"context_used":2113,"generation_tps":18.5,"prompt_tps":132,"memory_pool_gib":12,"memory_free_gib":1.9,"model_gib":8.2,"kv_cache_gib":1.1,"load_progress":null,"ready":true}"#.utf8))
        XCTAssertTrue(status.ready)
        XCTAssertEqual(status.modelID, list.models[0].id)
        XCTAssertEqual(status.contextSize, 32_768)
        XCTAssertEqual(status.contextUsed, 2_113)
        XCTAssertEqual(status.generationTPS, 18.5)
        XCTAssertEqual(status.promptTPS, 132)
        XCTAssertEqual(status.memoryPoolGiB, 12)
        XCTAssertEqual(status.memoryFreeGiB, 1.9)
        XCTAssertEqual(status.modelGiB, 8.2)
        XCTAssertEqual(status.kvCacheGiB, 1.1)
        XCTAssertNil(status.loadProgress)
    }

    func testWorkspaceBridgeResponseDecodesWithoutPathsOrCommandsInModel() throws {
        let list = try JSONDecoder().decode(PS5NexusWorkspaceList.self, from: Data(
            #"{"host":"debian","workspaces":[{"id":"nexus-app","name":"Nexus"}]}"#.utf8))
        XCTAssertEqual(list.host, "debian")
        XCTAssertTrue(list.workspaces[0].valid)
        let files = try JSONDecoder().decode(PS5NexusWorkspaceFiles.self, from: Data(
            #"{"host":"debian","workspace_id":"nexus-app","path":"src","entries":[{"name":"main.swift","path":"src/main.swift","kind":"file"}],"truncated":false}"#.utf8))
        XCTAssertEqual(files.workspaceID, "nexus-app")
        XCTAssertEqual(files.entries.first?.path, "src/main.swift")
        let context = try JSONDecoder().decode(PS5NexusWorkspaceContext.self, from: Data(
            #"{"host":"debian","workspace_id":"nexus-app","path":"src/main.swift","text":"print(1)","size_bytes":8}"#.utf8))
        XCTAssertEqual(context.text, "print(1)")
    }

    func testOrchestratorCanonicalCompactionAndSubagentStatusResponse() throws {
        let body = #"{"response":"Done","model":"Qwen","compacted":true,"finish_reason":"length","input_tokens":128,"reserved_output_tokens":900,"context_window_tokens":8192,"history_for_next_turn":[{"role":"assistant","content":"Done"}],"subagents":[{"role":"inventory","output":"2 files"}],"workspace":{"host":"nixos","workspace_id":"nexus-app","path":"src"},"workspace_tools":[{"tool":"find_text","path":"src","result_count":2}]}"#
        let result = try JSONDecoder().decode(PS5NexusOrchestratedResult.self, from: Data(body.utf8))
        XCTAssertTrue(result.compacted)
        XCTAssertEqual(result.finishReason, "length")
        XCTAssertEqual(result.inputTokens, 128)
        XCTAssertEqual(result.reservedOutputTokens, 900)
        XCTAssertEqual(result.contextWindowTokens, 8192)
        XCTAssertEqual(result.workspaceTools?.first?.tool, "find_text")
        XCTAssertEqual(result.workspaceTools?.first?.resultCount, 2)
        XCTAssertEqual(result.historyForNextTurn.first?.role, "assistant")
        XCTAssertEqual(result.subagents.first?.output, "2 files")
        XCTAssertEqual(result.workspace.workspaceID, "nexus-app")
    }

    func testConversationCompactionChoiceSurvivesRestoreAndLegacyDefaults() throws {
        let saved = PS5NexusOrchestratedConversation(automaticCompactionEnabled: false)
        let data = try JSONEncoder().encode(saved)
        let restored = try JSONDecoder().decode(PS5NexusOrchestratedConversation.self, from: data)
        XCTAssertTrue(restored.isValid)
        XCTAssertFalse(restored.effectiveAutomaticCompaction)

        var legacy = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        legacy.removeValue(forKey: "automaticCompactionEnabled")
        let old = try JSONDecoder().decode(PS5NexusOrchestratedConversation.self,
            from: JSONSerialization.data(withJSONObject: legacy))
        XCTAssertNil(old.automaticCompactionEnabled)
        XCTAssertTrue(old.effectiveAutomaticCompaction)

        legacy["automaticCompactionEnabled"] = "false"
        XCTAssertThrowsError(try JSONDecoder().decode(PS5NexusOrchestratedConversation.self,
            from: JSONSerialization.data(withJSONObject: legacy)))
    }

    func testSavedTaskKeepsOriginalCompactionPolicyDuringRecovery() throws {
        let pending = PS5NexusPendingSubmission(id: "0123456789abcdef0123456789abcdef",
            prompt: "original task", history: [], subagents: 0, autoCompact: true)
        let saved = PS5NexusOrchestratedConversation(pendingPrompt: pending.prompt,
            pendingSubmission: pending, automaticCompactionEnabled: false)
        var restored = try JSONDecoder().decode(PS5NexusOrchestratedConversation.self,
            from: JSONEncoder().encode(saved))
        XCTAssertTrue(restored.isValid)
        XCTAssertTrue(restored.effectiveAutomaticCompaction)
        XCTAssertEqual(restored.pendingSubmission, pending)
        restored.pendingSubmission = nil
        restored.pendingPrompt = nil
        XCTAssertFalse(restored.effectiveAutomaticCompaction)
        XCTAssertFalse(saved.canResume(runID: pending.id, credential: UUID(), scope: String(repeating: "a", count: 64)))
    }

    func testOrchestratedTranscriptKeepsFullTurnsSeparateFromCompactedContext() throws {
        let turns = [PS5NexusOrchestratedTurn(prompt: "first", response: "answer one",
                                               model: "Qwen", finishReason: "length", status: "completed"),
                     PS5NexusOrchestratedTurn(prompt: "second", status: "cancelled"),
                     PS5NexusOrchestratedTurn(prompt: "third", status: "failed")]
        let transcript = PS5NexusOrchestratedConversation(
            turns: turns,
            contextHistory: [PS5NexusOrchestratedMessage(role: "assistant", content: "checkpoint")],
            pendingPrompt: "fourth", compactions: [PS5NexusCompactionRecord(summary: "saved summary")])
        XCTAssertTrue(transcript.isValid)
        let decoded = try JSONDecoder().decode(PS5NexusOrchestratedConversation.self,
                                              from: JSONEncoder().encode(transcript))
        XCTAssertEqual(decoded, transcript)
        XCTAssertEqual(decoded.turns.map(\.prompt), ["first", "second", "third"])
        XCTAssertEqual(decoded.turns.first?.finishReason, "length")
        XCTAssertEqual(decoded.turns.last?.status, "failed")
        XCTAssertEqual(decoded.contextHistory.first?.content, "checkpoint")
        XCTAssertEqual(decoded.pendingPrompt, "fourth")
        XCTAssertEqual(decoded.compactions?.first?.summary, "saved summary")

        let pending = PS5NexusPendingSubmission(id: "0123456789abcdef0123456789abcdef",
            prompt: "fourth", history: transcript.contextHistory, subagents: 1, autoCompact: true)
        var recoverable = transcript
        recoverable.pendingSubmission = pending
        XCTAssertTrue(recoverable.isValid)
        XCTAssertEqual(try JSONDecoder().decode(PS5NexusOrchestratedConversation.self,
            from: JSONEncoder().encode(recoverable)).pendingSubmission, pending)
        recoverable.pendingPrompt = "different task"
        XCTAssertFalse(recoverable.isValid)

        var legacy = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(transcript)) as? [String: Any])
        legacy.removeValue(forKey: "pendingSubmission")
        legacy.removeValue(forKey: "compactions")
        var legacyTurns = try XCTUnwrap(legacy["turns"] as? [[String: Any]])
        legacyTurns[0].removeValue(forKey: "finishReason")
        legacy["turns"] = legacyTurns
        let legacyData = try JSONSerialization.data(withJSONObject: legacy)
        let decodedLegacy = try JSONDecoder().decode(PS5NexusOrchestratedConversation.self, from: legacyData)
        XCTAssertNil(decodedLegacy.pendingSubmission)
        XCTAssertNil(decodedLegacy.compactions)
        XCTAssertNil(decodedLegacy.turns.first?.finishReason)

        let longerReply = PS5NexusOrchestratedTurn(prompt: "code", response: String(repeating: "x", count: 16_000),
                                                   model: "Qwen", status: "completed")
        XCTAssertTrue(PS5NexusOrchestratedConversation(turns: [longerReply],
            contextHistory: [PS5NexusOrchestratedMessage(role: "assistant", content: longerReply.response!)]).isValid)
        let oversizedReply = PS5NexusOrchestratedTurn(prompt: "code", response: String(repeating: "x", count: 48 * 1_024 + 1),
                                                     model: "Qwen", status: "completed")
        XCTAssertFalse(oversizedReply.isValid)

        let invalidRole = PS5NexusOrchestratedConversation(
            contextHistory: [PS5NexusOrchestratedMessage(role: "system", content: "untrusted")])
        XCTAssertFalse(invalidRole.isValid)
        let invalidTurn = PS5NexusOrchestratedConversation(
            turns: [PS5NexusOrchestratedTurn(prompt: "", status: "completed")])
        XCTAssertFalse(invalidTurn.isValid)
        let tooManyContextMessages = PS5NexusOrchestratedConversation(contextHistory: Array(
            repeating: PS5NexusOrchestratedMessage(role: "user", content: "x"), count: 33))
        XCTAssertFalse(tooManyContextMessages.isValid)
    }

    func testDurableAgentRunProgressDecodesQueuedAndTerminalChildStates() throws {
        let body = #"{"id":"0123456789abcdef0123456789abcdef","status":"running","phase":"subagent analyzer","created_at":1793439000,"updated_at":1793439001,"cancel_requested":false,"subagents":[{"id":"abcdef0123456789abcdef0123456789","role":"analyzer","status":"cancelling"}],"events":[{"at":1793439001,"phase":"subagent analyzer","status":"running","subagent_index":0,"subagent_status":"running"}],"result":null,"error":null}"#
        let progress = try JSONDecoder().decode(PS5NexusRunProgress.self, from: Data(body.utf8))
        XCTAssertEqual(progress.status, "running")
        XCTAssertEqual(progress.phase, "subagent analyzer")
        XCTAssertEqual(progress.subagents.first?.status, "cancelling")
        XCTAssertEqual(progress.events?.first?.subagentIndex, 0)
        XCTAssertEqual(progress.events?.first?.subagentStatus, "running")

        let completedBody = #"{"id":"0123456789abcdef0123456789abcdef","status":"completed","phase":"completed","created_at":1793439000,"updated_at":1793439001,"cancel_requested":false,"subagents":[{"id":"abcdef0123456789abcdef0123456789","role":"analyzer","status":"cancelled"}],"result":{"response":"Done","model":"Qwen","compacted":false,"history_for_next_turn":[],"subagents":[],"workspace":{"host":"debian","workspace_id":"nexus-app","path":"src"}},"error":null}"#
        let completed = try JSONDecoder().decode(PS5NexusRunProgress.self, from: Data(completedBody.utf8))
        XCTAssertEqual(completed.subagents.first?.status, "cancelled")
        XCTAssertEqual(completed.result?.response, "Done")
    }
}

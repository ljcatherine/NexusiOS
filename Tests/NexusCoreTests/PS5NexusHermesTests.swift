import Foundation
import XCTest
@testable import NexusCore

final class PS5NexusHermesTests: XCTestCase {
    func testEngineChoiceSurvivesPendingRequestRecovery() throws {
        let pending = PS5NexusPendingSubmission(id: String(repeating: "a", count: 32),
            prompt: "Inspect the workspace", history: [], subagents: 0,
            autoCompact: true, engine: .hermes)
        XCTAssertTrue(pending.isValid)
        let body = try JSONEncoder().encode(pending)
        let restored = try JSONDecoder().decode(PS5NexusPendingSubmission.self, from: body)
        XCTAssertEqual(restored.engine, .hermes)
        XCTAssertEqual(restored, pending)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: body) as? [String: Any])
        XCTAssertEqual(object["engine"] as? String, "hermes")
    }

    func testLegacyRequestDoesNotSilentlySelectHermes() throws {
        let body = Data(#"{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","prompt":"Inspect","history":[],"subagents":0,"autoCompact":true}"#.utf8)
        let restored = try JSONDecoder().decode(PS5NexusPendingSubmission.self, from: body)
        XCTAssertNil(restored.engine)
        XCTAssertEqual(restored.engine ?? .nexus, .nexus)
    }

    func testUnknownSavedEngineFailsRatherThanSwitchingRuntime() {
        let body = Data(#"{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","prompt":"Inspect","history":[],"subagents":0,"autoCompact":true,"engine":"unknown"}"#.utf8)
        XCTAssertThrowsError(try JSONDecoder().decode(PS5NexusPendingSubmission.self, from: body))
    }
}

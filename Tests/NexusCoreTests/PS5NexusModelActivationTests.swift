import Foundation
import XCTest
@testable import NexusCore

private actor ModelActivationFixture: PS5NexusModelManaging {
    var results: [Result<PS5NexusStatus, PS5NexusError>]
    var loads = 0
    var reads = 0
    let loadError: PS5NexusError?
    init(_ results: [Result<PS5NexusStatus, PS5NexusError>], loadError: PS5NexusError? = nil) {
        self.results = results
        self.loadError = loadError
    }
    func load(modelID: String, endpoint: PS5NexusEndpoint, token: String) async throws {
        loads += 1
        if let loadError { throw loadError }
    }
    func status(endpoint: PS5NexusEndpoint, token: String) async throws -> PS5NexusStatus {
        reads += 1
        return try (results.isEmpty ? .failure(.unavailable) : results.removeFirst()).get()
    }
    func counts() -> [Int] { [loads, reads] }
}

final class PS5NexusModelActivationTests: XCTestCase {
    private let target = "0123456789abcdef"
    private func endpoint() throws -> PS5NexusEndpoint {
        let connection = AIConnection(name: "Fixture", provider: .customOpenAICompatible,
                                      baseURL: "https://example.test/v1")
        return try PS5NexusEndpoint(managementURL: connection.baseURL, connection: connection,
                                    reuseConnectionCredential: true)
    }
    private func state(_ id: String = "0123456789abcdef", ready: Bool = true) throws -> PS5NexusStatus {
        try JSONDecoder().decode(PS5NexusStatus.self,
            from: JSONSerialization.data(withJSONObject: ["state": ready ? "ready" : "loading",
                                                          "model_id": id, "ready": ready]))
    }
    func testLateReadinessAndWrongModelDoNotReplayLoad() async throws {
        var results: [Result<PS5NexusStatus, PS5NexusError>] = Array(repeating: .failure(.failed(503)), count: 26)
        results += [.success(try state("fedcba9876543210")), .success(try state(ready: false)),
                    .success(try state())]
        let fixture = ModelActivationFixture(results)
        let outcome = try await PS5NexusModelActivation.submitAndObserve(modelID: target,
            endpoint: endpoint(), token: "fixture", client: fixture, pause: {})
        XCTAssertEqual(outcome, .ready(try state()))
        let counts = await fixture.counts()
        XCTAssertEqual(counts, [1, 29]) // readiness well beyond the former eight polls
    }
    func testObservingAnAcceptedLoadNeverSubmitsAnother() async throws {
        let fixture = ModelActivationFixture([.failure(.failed(503)), .success(try state(ready: false)),
                                              .success(try state())])
        let outcome = try await PS5NexusModelActivation.observe(modelID: target,
            endpoint: endpoint(), token: "fixture", client: fixture, pause: {})
        XCTAssertEqual(outcome, .ready(try state()))
        let counts = await fixture.counts()
        XCTAssertEqual(counts, [0, 3])
    }
    func testUnconfirmedReadinessNeverSelectsAndStopsPolling() async throws {
        let fixture = ModelActivationFixture([])
        let outcome = try await PS5NexusModelActivation.submitAndObserve(modelID: target,
            endpoint: endpoint(), token: "fixture", client: fixture, pause: {})
        XCTAssertEqual(outcome, .unconfirmed(nil))
        let counts = await fixture.counts()
        XCTAssertEqual(counts, [1, 45])
    }
    func testUnconfirmedOutcomeReportsTheLastModelSeen() async throws {
        let other = try state("fedcba9876543210")
        let fixture = ModelActivationFixture(Array(repeating: .success(other), count: 45))
        let outcome = try await PS5NexusModelActivation.submitAndObserve(modelID: target,
            endpoint: endpoint(), token: "fixture", client: fixture, pause: {})
        XCTAssertEqual(outcome, .unconfirmed(other))
    }
    func testAuthorizationFailureStopsImmediately() async throws {
        for failure in [PS5NexusError.unauthorized, .forbidden, .invalidResponse] {
            let fixture = ModelActivationFixture([.failure(failure)])
            do {
                _ = try await PS5NexusModelActivation.submitAndObserve(modelID: target,
                    endpoint: endpoint(), token: "fixture", client: fixture, pause: {})
                XCTFail("Expected fail-closed status rejection")
            } catch { XCTAssertEqual(error as? PS5NexusError, failure) }
            let counts = await fixture.counts()
            XCTAssertEqual(counts, [1, 1])
        }
    }
    func testAmbiguousSubmissionIsObservedButNotRetried() async throws {
        let fixture = ModelActivationFixture([.success(try state())], loadError: .unavailable)
        let outcome = try await PS5NexusModelActivation.submitAndObserve(modelID: target,
            endpoint: endpoint(), token: "fixture", client: fixture, pause: {})
        XCTAssertEqual(outcome, .ready(try state()))
        let counts = await fixture.counts()
        XCTAssertEqual(counts, [1, 1])
    }
    func testDefiniteRejectionEndsWithoutStatusReads() async throws {
        for failure in [PS5NexusError.unauthorized, .forbidden, .failed(409), .failed(429)] {
            let fixture = ModelActivationFixture([], loadError: failure)
            let outcome = try await PS5NexusModelActivation.submitAndObserve(modelID: target,
                endpoint: endpoint(), token: "fixture", client: fixture, pause: {})
            XCTAssertEqual(outcome, .rejected(failure))
            let counts = await fixture.counts()
            XCTAssertEqual(counts, [1, 0])
        }
    }
    func testWaitThatExpiredInTheBackgroundStillReadsOnceMore() async throws {
        let fixture = ModelActivationFixture([.success(try state())])
        let outcome = try await PS5NexusModelActivation.observe(modelID: target,
            endpoint: endpoint(), token: "fixture", client: fixture, timeout: .zero, pause: {})
        XCTAssertEqual(outcome, .ready(try state()))
    }
    func testChatModelIsResolvedAfterGatewayFinishesConfirmingSwitch() async throws {
        var replies: [[String]] = [[], [], ["q6.gguf"]]
        let model = try await PS5NexusModelActivation.resolveChatModel(
            fetch: { replies.removeFirst() }, pause: {})
        XCTAssertEqual(model, "q6.gguf")
        XCTAssertTrue(replies.isEmpty)
    }
    func testChatModelResolutionIsBoundedAndNeverGuesses() async throws {
        var calls = 0
        do {
            let _: String = try await PS5NexusModelActivation.resolveChatModel(
                fetch: { calls += 1; return [] }, pause: {})
            XCTFail("Expected no model to be selected")
        } catch { XCTAssertEqual(error as? PS5NexusError, .invalidResponse) }
        XCTAssertEqual(calls, 5)
        calls = 0
        do {
            let _: String = try await PS5NexusModelActivation.resolveChatModel(
                fetch: { calls += 1; return ["a", "b"] }, pause: {})
            XCTFail("Expected an ambiguous list to be refused")
        } catch { XCTAssertEqual(error as? PS5NexusError, .invalidResponse) }
        XCTAssertEqual(calls, 1)
    }
    func testCancellationAfterSubmissionStopsReadsWithoutAnotherLoad() async throws {
        let fixture = ModelActivationFixture([])
        do {
            _ = try await PS5NexusModelActivation.submitAndObserve(modelID: target,
                endpoint: endpoint(), token: "fixture", client: fixture,
                pause: { throw CancellationError() })
            XCTFail("Expected cancellation")
        } catch { XCTAssertTrue(error is CancellationError) }
        let counts = await fixture.counts()
        XCTAssertEqual(counts, [1, 0])
    }
}

final class PS5NexusModelLoadTrackerTests: XCTestCase {
    private let connection = UUID()
    private let q6 = PS5NexusModel(id: "aaaaaaaaaaaaaaaa", label: "Q6", drive: "", fits: true, current: false)
    private let q4 = PS5NexusModel(id: "bbbbbbbbbbbbbbbb", label: "Q4", drive: "", fits: true, current: false)
    private func status(_ model: PS5NexusModel, ready: Bool = true) throws -> PS5NexusStatus {
        try JSONDecoder().decode(PS5NexusStatus.self,
            from: JSONSerialization.data(withJSONObject: ["state": ready ? "ready" : "loading",
                                                          "model_id": model.id, "ready": ready]))
    }
    private func observing(_ tracker: inout PS5NexusModelLoadTracker) throws -> UUID {
        let id = try XCTUnwrap(tracker.begin(q6, connectionID: connection))
        tracker.markSubmitted(id, connectionID: connection)
        return id
    }

    func testSecondLoadIsRefusedWhileOneIsActiveOnAnyConnection() throws {
        var tracker = PS5NexusModelLoadTracker()
        _ = try observing(&tracker)
        XCTAssertNil(tracker.begin(q4, connectionID: connection))
        XCTAssertNil(tracker.begin(q4, connectionID: UUID()))
    }
    func testReadinessActivatesOnceAndUnblocksSending() throws {
        var tracker = PS5NexusModelLoadTracker()
        let id = try observing(&tracker)
        XCTAssertEqual(tracker.reconcile(try status(q6, ready: false), connectionID: connection), .none)
        XCTAssertEqual(tracker.reconcile(try status(q6), connectionID: connection), .activate(id))
        // A manual refresh overlapping the background task must not activate again.
        XCTAssertEqual(tracker.reconcile(try status(q6), connectionID: connection), .none)
        XCTAssertNotNil(tracker.entry(for: connection))
        XCTAssertTrue(tracker.complete(id, connectionID: connection))
        XCTAssertFalse(tracker.complete(id, connectionID: connection))
        XCTAssertNil(tracker.entry(for: connection))
    }
    func testOldModelStillReadyWhileObservingKeepsSendingBlocked() throws {
        var tracker = PS5NexusModelLoadTracker()
        _ = try observing(&tracker)
        XCTAssertEqual(tracker.reconcile(try status(q4), connectionID: connection), .none)
        XCTAssertEqual(tracker.entry(for: connection)?.phase, .observing)
    }
    func testUnconfirmedLoadEndsWhenADifferentModelIsReady() throws {
        var tracker = PS5NexusModelLoadTracker()
        let id = try observing(&tracker)
        tracker.markUnconfirmed(id, connectionID: connection, issue: "Unknown")
        XCTAssertEqual(tracker.reconcile(try status(q4), connectionID: connection), .superseded)
        XCTAssertNil(tracker.entry(for: connection))
        XCTAssertTrue(tracker.issue(for: connection)?.contains("Q6") == true)
    }
    func testUnconfirmedLoadCanStillSucceedLater() throws {
        var tracker = PS5NexusModelLoadTracker()
        let id = try observing(&tracker)
        tracker.markUnconfirmed(id, connectionID: connection, issue: "Unknown")
        XCTAssertEqual(tracker.reconcile(try status(q6), connectionID: connection), .activate(id))
        XCTAssertNil(tracker.issue(for: connection))
    }
    func testUnconfirmedLoadBlocksOnlyItsOwnConnection() throws {
        var tracker = PS5NexusModelLoadTracker()
        let id = try observing(&tracker)
        tracker.markUnconfirmed(id, connectionID: connection, issue: "Unknown")
        XCTAssertNil(tracker.begin(q4, connectionID: connection))
        XCTAssertNotNil(tracker.begin(q4, connectionID: UUID()))
    }
    func testStoppingUnblocksSendingAndIgnoresLateResults() throws {
        var tracker = PS5NexusModelLoadTracker()
        let first = try observing(&tracker)
        XCTAssertEqual(tracker.stop(connectionID: connection), first)
        XCTAssertNil(tracker.entry(for: connection))
        let second = try observing(&tracker)
        tracker.markUnconfirmed(first, connectionID: connection, issue: "Stale")
        tracker.reject(first, connectionID: connection, issue: "Stale")
        XCTAssertFalse(tracker.complete(first, connectionID: connection))
        XCTAssertEqual(tracker.entry(for: connection)?.id, second)
        XCTAssertEqual(tracker.entry(for: connection)?.phase, .observing)
        XCTAssertNil(tracker.issue(for: connection))
    }
    func testRejectionUnblocksSendingAndKeepsTheReason() throws {
        var tracker = PS5NexusModelLoadTracker()
        let id = try observing(&tracker)
        tracker.reject(id, connectionID: connection, issue: "Refused")
        XCTAssertNil(tracker.entry(for: connection))
        XCTAssertEqual(tracker.issue(for: connection), "Refused")
    }
}

import Foundation

public protocol PS5NexusModelManaging: Sendable {
    func load(modelID: String, endpoint: PS5NexusEndpoint, token: String) async throws
    func status(endpoint: PS5NexusEndpoint, token: String) async throws -> PS5NexusStatus
}

extension PS5NexusHTTPClient: PS5NexusModelManaging {}

public enum PS5NexusLoadOutcome: Equatable, Sendable {
    /// The requested model reported ready.
    case ready(PS5NexusStatus)
    /// The bounded wait ended without confirmation. The caller must not select
    /// the model. Carries the last status read, if any succeeded.
    case unconfirmed(PS5NexusStatus?)
    /// The server definitely refused the load, so nothing is restarting.
    case rejected(PS5NexusError)
}

/// One load submission followed only by bounded, authenticated status reads.
public enum PS5NexusModelActivation {
    /// Sends the load exactly once. A lost or unclear reply may still have
    /// started the load, so it is observed rather than reported as a failure.
    public static func submitAndObserve(
        modelID: String, endpoint: PS5NexusEndpoint, token: String,
        client: any PS5NexusModelManaging = PS5NexusHTTPClient(),
        pause: @Sendable () async throws -> Void = { try await Task.sleep(for: .seconds(4)) }
    ) async throws -> PS5NexusLoadOutcome {
        try Task.checkCancellation()
        do {
            try await client.load(modelID: modelID, endpoint: endpoint, token: token)
        } catch let error as PS5NexusError where isDefiniteRejection(error) {
            return .rejected(error)
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            // Ambiguous submission: continue with reads only.
        }
        return try await observe(modelID: modelID, endpoint: endpoint, token: token,
                                 client: client, pause: pause)
    }

    /// Observes an already submitted load without sending it again.
    public static func observe(
        modelID: String, endpoint: PS5NexusEndpoint, token: String,
        client: any PS5NexusModelManaging = PS5NexusHTTPClient(),
        timeout: Duration = .seconds(180),
        pause: @Sendable () async throws -> Void = { try await Task.sleep(for: .seconds(4)) }
    ) async throws -> PS5NexusLoadOutcome {
        let deadline = ContinuousClock.now.advanced(by: timeout)
        var latest: PS5NexusStatus?
        for _ in 0..<45 {
            try Task.checkCancellation()
            try await pause()
            try Task.checkCancellation()
            do {
                let state = try await client.status(endpoint: endpoint, token: token)
                if state.ready && state.modelID == modelID { return .ready(state) }
                latest = state
            } catch PS5NexusError.unavailable {
                // Restarting the inference listener temporarily drops reads.
                latest = nil
            } catch PS5NexusError.failed(let code) where [429, 502, 503, 504].contains(code) {
                // Never retry the load POST, even if a status read fails.
                latest = nil
            }
            // Checked after reading: iOS suspends this loop in the background,
            // and the wait can expire while the PS5 finishes loading.
            guard ContinuousClock.now < deadline else { break }
        }
        return .unconfirmed(latest)
    }

    /// Resolves the single advertised chat model after readiness. The gateway
    /// can briefly return no models while it confirms the finished switch.
    public static func resolveChatModel<Model>(
        attempts: Int = 5,
        isolation: isolated (any Actor)? = #isolation,
        fetch: () async throws -> [Model],
        pause: () async throws -> Void = { try await Task.sleep(for: .seconds(2)) }
    ) async throws -> Model {
        var failure: Error = PS5NexusError.invalidResponse
        for attempt in 0..<max(attempts, 1) {
            if attempt > 0 { try await pause() }
            try Task.checkCancellation()
            let advertised: [Model]
            do {
                advertised = try await fetch()
            } catch is CancellationError {
                throw CancellationError()
            } catch {
                failure = error
                continue
            }
            if advertised.count == 1 { return advertised[0] }
            guard advertised.isEmpty else { throw PS5NexusError.invalidResponse }
            failure = PS5NexusError.invalidResponse
        }
        throw failure
    }

    /// True only when the server's reply proves it did not accept the load.
    /// Transport failures and 5xx replies may follow an accepted submission.
    static func isDefiniteRejection(_ error: PS5NexusError) -> Bool {
        switch error {
        case .invalidEndpoint, .noCredential, .unauthorized, .forbidden, .requestTooLarge:
            true
        case .failed(let code):
            [400, 409, 413, 422, 429].contains(code)
        default:
            false
        }
    }
}

/// Which PS5 model loads are in progress, per AI connection. Sending stays
/// blocked for as long as a connection has an entry. Results from a load that
/// has been replaced or stopped are ignored through its `id`.
public struct PS5NexusModelLoadTracker: Equatable, Sendable {
    public enum Phase: Equatable, Sendable {
        /// Preparing or sending the single load request.
        case submitting
        /// Reading status while the PS5 restarts inference.
        case observing
        /// The PS5 reported ready; resolving the chat model identifier.
        case activating
        /// The wait ended without proof either way. Nothing is polling.
        case unconfirmed
    }

    public struct Entry: Equatable, Sendable {
        public let id: UUID
        public let model: PS5NexusModel
        public fileprivate(set) var phase: Phase
    }

    public enum Reconciliation: Equatable, Sendable {
        case none
        /// The target is ready. The caller alone resolves the chat model.
        case activate(UUID)
        /// A different model is ready, so this load is over and sending resumes.
        case superseded
    }

    private var entries: [UUID: Entry] = [:]
    private var issues: [UUID: String] = [:]

    public init() {}

    public func entry(for connectionID: UUID) -> Entry? { entries[connectionID] }
    public func issue(for connectionID: UUID) -> String? { issues[connectionID] }

    /// A connection waits for its own load to resolve. A stale unconfirmed load
    /// elsewhere does not block it, but an active restart anywhere does.
    public func canBegin(connectionID: UUID) -> Bool {
        entries[connectionID] == nil && !entries.values.contains { $0.phase != .unconfirmed }
    }

    public mutating func begin(_ model: PS5NexusModel, connectionID: UUID) -> UUID? {
        guard canBegin(connectionID: connectionID) else { return nil }
        let id = UUID()
        entries[connectionID] = Entry(id: id, model: model, phase: .submitting)
        issues[connectionID] = nil
        return id
    }

    /// Call immediately before the load request is sent.
    public mutating func markSubmitted(_ id: UUID, connectionID: UUID) {
        guard entries[connectionID]?.id == id, entries[connectionID]?.phase == .submitting else { return }
        entries[connectionID]?.phase = .observing
    }

    /// Ends a load that never reached the PS5 or that the PS5 refused.
    public mutating func reject(_ id: UUID, connectionID: UUID, issue: String) {
        guard entries[connectionID]?.id == id else { return }
        entries[connectionID] = nil
        issues[connectionID] = issue
    }

    public mutating func markUnconfirmed(_ id: UUID, connectionID: UUID, issue: String) {
        guard entries[connectionID]?.id == id else { return }
        entries[connectionID]?.phase = .unconfirmed
        issues[connectionID] = issue
    }

    public mutating func recordIssue(_ issue: String, connectionID: UUID) {
        guard entries[connectionID] != nil else { return }
        issues[connectionID] = issue
    }

    /// Applies a status report. A different ready model only ends an unconfirmed
    /// load: while observing, the old model can still report ready for a moment.
    public mutating func reconcile(_ status: PS5NexusStatus, connectionID: UUID) -> Reconciliation {
        guard let entry = entries[connectionID], status.ready,
              entry.phase == .observing || entry.phase == .unconfirmed else { return .none }
        if status.modelID == entry.model.id {
            entries[connectionID]?.phase = .activating
            issues[connectionID] = nil
            return .activate(entry.id)
        }
        guard entry.phase == .unconfirmed else { return .none }
        entries[connectionID] = nil
        issues[connectionID] = "\(entry.model.label) did not load. The PS5 is ready with a different model."
        return .superseded
    }

    /// True once for the load that finished, so one activation is published.
    public mutating func complete(_ id: UUID, connectionID: UUID) -> Bool {
        guard entries[connectionID]?.id == id, entries[connectionID]?.phase == .activating else { return false }
        entries[connectionID] = nil
        issues[connectionID] = nil
        return true
    }

    /// Stops waiting locally. An accepted server-side load is not undone, and
    /// the gateway still refuses inference until the PS5 is ready.
    @discardableResult
    public mutating func stop(connectionID: UUID) -> UUID? {
        issues[connectionID] = nil
        return entries.removeValue(forKey: connectionID)?.id
    }
}

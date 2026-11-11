import Foundation
import Network
import NexusCore

enum EndpointProbeResult: Equatable, Sendable {
    case reachable(milliseconds: Int)
    case failed(String)

    var summary: String {
        switch self {
        case .reachable(let milliseconds): return "TCP reachable · \(milliseconds) ms"
        case .failed(let reason): return reason
        }
    }
}

/// Checks only whether a TCP listener accepts a connection; it does not authenticate SSH.
enum EndpointProbe {
    static func check(_ endpoint: Endpoint, timeout: TimeInterval = 6) async -> EndpointProbeResult {
        guard (1...65535).contains(endpoint.port),
              let port = NWEndpoint.Port(rawValue: UInt16(endpoint.port)) else {
            return .failed("Invalid port")
        }
        let connection = NWConnection(host: NWEndpoint.Host(endpoint.host), port: port, using: .tcp)
        let queue = DispatchQueue(label: "com.ljcatherine.Nexus.endpoint-probe")
        let attempt = ProbeAttempt(connection: connection, timeout: timeout)
        return await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                attempt.start(continuation, on: queue)
            }
        } onCancel: {
            attempt.cancel()
        }
    }
}

private final class ProbeAttempt: @unchecked Sendable {
    private let connection: NWConnection
    private let timeout: TimeInterval
    private let startedAt = DispatchTime.now().uptimeNanoseconds
    private let lock = NSLock()
    private var continuation: CheckedContinuation<EndpointProbeResult, Never>?
    private var completed = false

    init(connection: NWConnection, timeout: TimeInterval) {
        self.connection = connection
        self.timeout = timeout
    }

    func start(_ continuation: CheckedContinuation<EndpointProbeResult, Never>, on queue: DispatchQueue) {
        lock.lock()
        guard !completed else { lock.unlock(); continuation.resume(returning: .failed("Connection cancelled")); return }
        self.continuation = continuation
        lock.unlock()
        connection.stateUpdateHandler = { [weak self] state in self?.update(state) }
        connection.start(queue: queue)
        startTimeout(on: queue)
    }

    func cancel() { finish(.failed("Connection cancelled")) }

    func startTimeout(on queue: DispatchQueue) {
        queue.asyncAfter(deadline: .now() + timeout) { [weak self] in
            self?.finish(.failed("Timed out after \(Int(self?.timeout ?? 0)) seconds"))
        }
    }

    func update(_ state: NWConnection.State) {
        switch state {
        case .ready:
            let elapsed = DispatchTime.now().uptimeNanoseconds - startedAt
            finish(.reachable(milliseconds: Int(elapsed / 1_000_000)))
        case .failed(let error): finish(.failed(error.localizedDescription))
        case .cancelled: finish(.failed("Connection cancelled"))
        default: break
        }
    }

    private func finish(_ result: EndpointProbeResult) {
        lock.lock()
        guard !completed else { lock.unlock(); return }
        completed = true
        let pending = continuation
        continuation = nil
        lock.unlock()
        connection.stateUpdateHandler = nil
        connection.cancel()
        pending?.resume(returning: result)
    }
}

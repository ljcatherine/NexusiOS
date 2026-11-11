import Foundation
import Dispatch

public enum DNSResolutionResult: Equatable, Sendable {
    case resolved(addresses: [String], milliseconds: Int)
    case failed(String)
}

/// Runs a blocking system resolver away from the caller and returns on timeout or cancellation.
/// The lookup itself may finish later because getaddrinfo cannot be interrupted portably.
public enum BoundedDNSResolver {
    private static let resolverQueue = DispatchQueue(label: "com.ljcatherine.Nexus.dns-resolution",
        qos: .utility)

    public static func resolve(host: String, timeout: TimeInterval = 8,
                               lookup: @escaping @Sendable (String) -> DNSResolutionResult) async -> DNSResolutionResult {
        let boundedTimeout = timeout.isFinite ? min(max(timeout, 0.01), 120) : 8
        let attempt = DNSLookupAttempt(host: host, timeout: boundedTimeout, lookup: lookup)
        return await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                attempt.start(continuation, resolverQueue: resolverQueue)
            }
        } onCancel: {
            attempt.cancel()
        }
    }
}

private final class DNSLookupAttempt: @unchecked Sendable {
    private let host: String
    private let timeout: TimeInterval
    private let lookup: @Sendable (String) -> DNSResolutionResult
    private let lock = NSLock()
    private var continuation: CheckedContinuation<DNSResolutionResult, Never>?
    private var finished = false

    init(host: String, timeout: TimeInterval,
         lookup: @escaping @Sendable (String) -> DNSResolutionResult) {
        self.host = host
        self.timeout = timeout
        self.lookup = lookup
    }

    func start(_ continuation: CheckedContinuation<DNSResolutionResult, Never>,
               resolverQueue: DispatchQueue) {
        lock.lock()
        guard !finished else {
            lock.unlock()
            continuation.resume(returning: .failed("Lookup cancelled"))
            return
        }
        self.continuation = continuation
        lock.unlock()

        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + timeout) { [self] in
            finish(.failed("Timed out after \(Int(ceil(timeout))) seconds"))
        }
        resolverQueue.async { [self] in
            guard isPending else { return }
            finish(lookup(host))
        }
    }

    func cancel() {
        finish(.failed("Lookup cancelled"))
    }

    private func finish(_ result: DNSResolutionResult) {
        lock.lock()
        guard !finished else { lock.unlock(); return }
        finished = true
        let pending = continuation
        continuation = nil
        lock.unlock()
        pending?.resume(returning: result)
    }

    private var isPending: Bool {
        lock.lock()
        defer { lock.unlock() }
        return !finished
    }
}

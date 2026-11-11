import Foundation
import Citadel
import NIOCore
import NIOSSH
import NexusCore

public enum SSHConnectionStage: String, Sendable {
    case checkingProfile, loadingKey, unlockingKey, connecting, openingShell, connected
    public var title: String {
        switch self {
        case .checkingProfile: return "Checking connection settings"
        case .loadingKey: return "Loading private key from Keychain"
        case .unlockingKey: return "Unlocking private key"
        case .connecting: return "Connecting and verifying server identity"
        case .openingShell: return "Opening interactive shell"
        case .connected: return "Connected"
        }
    }
}

/// Retains the user-facing classification while carrying only a bounded low-level
/// error type/code chain for diagnosis. It never includes error domains/descriptions,
/// hostnames, usernames, keys, or passphrases.
public struct SSHHandshakeFailure: LocalizedError, Sendable {
    public let failure: SSHFailure
    public let diagnostic: String
    public var errorDescription: String? { failure.errorDescription }
    public var allowsEndpointFallback: Bool { failure.allowsEndpointFallback }
}

/// Builds a bounded diagnostic without copying arbitrary NSError domains or localized
/// descriptions, either of which may contain runtime-provided endpoint or user data.
public enum SSHDiagnosticFormatter {
    static func protocolErrorName(_ type: NIOSSHError.ErrorType) -> String {
        String(type.description.unicodeScalars
            .filter { CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "._")).contains($0) }
            .map(String.init)
            .joined()
            .prefix(80))
    }

    public static func describe(_ error: Error) -> String {
        var items: [String] = []
        var current: Error? = error
        for _ in 0..<4 {
            guard let value = current else { break }
            let nsError = value as NSError
            let typeName = String(reflecting: type(of: value))
                .unicodeScalars
                .filter { CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "._" )).contains($0) }
                .map(String.init)
                .joined()
            let caseName: String
            if let failure = value as? SSHFailure {
                caseName = " (\(failure.diagnosticName))"
            } else if let sshError = value as? NIOSSHError {
                caseName = " (\(protocolErrorName(sshError.type)))"
            } else {
                caseName = ""
            }
            items.append("\(typeName.prefix(96))\(caseName) · code \(nsError.code)")
            current = nsError.userInfo[NSUnderlyingErrorKey] as? Error
        }
        return items.isEmpty ? "Unknown SSH error" : items.joined(separator: " ← ")
    }
}

/// A replaceable boundary around the actual SSH handshake, not around cryptography or trust policy.
public protocol SSHConnectionBackend: Sendable {
    func connect(settings: SSHClientSettings) async throws -> SSHClient
}

public protocol SSHCloudflareConnectionBackend: Sendable {
    func connect(settings: SSHClientSettings, target: String, accessToken: String) async throws -> SSHClient
}

public struct CitadelConnectionBackend: SSHConnectionBackend, SSHCloudflareConnectionBackend {
    public init() {}
    public func connect(settings: SSHClientSettings) async throws -> SSHClient {
        try await SSHClientConnector.connect(to: settings)
    }
    public func connect(settings: SSHClientSettings, target: String, accessToken: String) async throws -> SSHClient {
        try await CloudflareSSHConnector.connect(settings: settings, target: target, accessToken: accessToken)
    }
}

/// One preparation path for every app feature. Expensive key decoding runs on this actor,
/// not the UI actor. Live connections remain owned by their individual transports.
public actor SSHConnectionPipeline {
    public static let shared = SSHConnectionPipeline()
    private let backend: any SSHConnectionBackend
    private var cloudflareAccessTokenProvider: (@Sendable () async throws -> String)?

    public init(backend: any SSHConnectionBackend = CitadelConnectionBackend()) {
        self.backend = backend
    }

    public func installCloudflareAccessTokenProvider(_ provider: @escaping @Sendable () async throws -> String) {
        cloudflareAccessTokenProvider = provider
    }

    public func validateCredential(for device: Device, credential: Credential) throws {
        try Task.checkCancellation()
        _ = try SSHTransport.authentication(device: device, credential: credential)
        try Task.checkCancellation()
    }

    public func connect(device: Device, endpoint: Endpoint, secrets: any SecretStore, timeout: Int,
                        onStage: @escaping @Sendable (SSHConnectionStage) async -> Void = { _ in }) async throws -> SSHClient {
        try Task.checkCancellation()
        await onStage(.checkingProfile)
        try device.validate()
        let selectedEndpoint = Self.cloudflareEndpoint(for: device, selected: endpoint) ?? endpoint
        try selectedEndpoint.validate()
        guard !selectedEndpoint.isExampleAddress else { throw SSHFailure.exampleEndpoint }
        let cloudflareTarget = selectedEndpoint.kind == .cloudflare ? selectedEndpoint.relayTarget : nil
        let authentication: SSHAuthenticationMethod
        let accessToken: String?
        if let cloudflareTarget {
            guard let cloudflareAccessTokenProvider else { throw SSHFailure.cloudflareSignInRequired }
            do { accessToken = try await cloudflareAccessTokenProvider() }
            catch { throw SSHFailure.cloudflareSignInRequired }
            guard let accessToken, !accessToken.isEmpty else { throw SSHFailure.cloudflareSignInRequired }
            authentication = .preauthenticated(username: device.username)
        } else {
            accessToken = nil
            guard device.authentication == .ed25519 else { throw SSHFailure.missingCredential }
            await onStage(.loadingKey)
            guard let data = try secrets.read(SSHTransport.credentialAccount(device)) else {
                throw SSHFailure.missingCredential
            }
            guard data.count <= 400 * 1024 else { throw SSHFailure.invalidCredentialRecord }
            let credential: Credential
            do { credential = try JSONDecoder().decode(Credential.self, from: data) }
            catch { throw SSHFailure.invalidCredentialRecord }
            try Task.checkCancellation()
            await onStage(.unlockingKey)
            authentication = try SSHTransport.authentication(device: device, credential: credential)
        }
        try Task.checkCancellation()
        let verifier = HostKeyVerifier(endpoint: selectedEndpoint, secrets: secrets)
        var settings = SSHClientSettings(host: selectedEndpoint.host, port: selectedEndpoint.port,
            authenticationMethod: { authentication }, hostKeyValidator: .custom(verifier))
        let seconds = max(3, min(timeout, 120))
        settings.connectTimeout = .seconds(Int64(seconds))
        await onStage(.connecting)
        do {
            let client = try await handshake(settings: settings, seconds: seconds,
                cloudflareTarget: cloudflareTarget, accessToken: accessToken)
            if Task.isCancelled {
                try? await client.close()
                throw CancellationError()
            }
            return client
        } catch {
            if Task.isCancelled || error is CancellationError { throw CancellationError() }
            if let challenge = verifier.challenge { throw challenge }
            if let failure = error as? SSHFailure { throw failure }
            let classified = Self.classifyHandshakeError(error)
            let reason: SSHFailure
            switch classified {
            case .authenticationRejected, .publicKeyAuthenticationUnavailable:
                reason = classified
            default:
                reason = verifier.didAcceptPinnedHostKey
                    ? .trustedEndpointHandshakeFailed
                    : classified
            }
            throw SSHHandshakeFailure(failure: reason, diagnostic: SSHDiagnosticFormatter.describe(error))
        }
    }

    private static func cloudflareEndpoint(for device: Device, selected: Endpoint) -> Endpoint? {
        let deployment = DeploymentConfiguration.current
        let target: String?
        if selected.kind == .cloudflare {
            target = selected.relayTarget
        } else {
            target = deployment.relayTarget(forUsername: device.username)
        }
        guard let target, let gatewayHost = deployment.gatewayHost else { return nil }
        return Endpoint(id: selected.id, host: gatewayHost,
            port: 443, kind: .cloudflare, priority: selected.priority, relayTarget: target)
    }

    static func classifyHandshakeError(_ error: Error) -> SSHFailure {
        if error is SocketAddressError.UnknownHost {
            return .endpointNameResolutionFailed
        }
        if let error = error as? SocketAddressError {
            if case .unknown = error { return .endpointNameResolutionFailed }
        }
        if let error = error as? SSHClientError {
            switch error {
            case .allAuthenticationOptionsFailed:
                return .authenticationRejected
            case .unsupportedPrivateKeyAuthentication:
                return .publicKeyAuthenticationUnavailable
            default:
                break
            }
        }
        if let error = error as? ChannelError, case .connectTimeout = error {
            return .connectionTimedOut
        }
        if let error = error as? IOError {
            switch POSIXErrorCode(rawValue: Int32(error.errnoCode)) {
            case .ECONNREFUSED: return .connectionRefused
            case .EHOSTUNREACH, .ENETUNREACH: return .networkUnreachable
            case .ETIMEDOUT: return .connectionTimedOut
            default: break
            }
        }
        return .connectionFailed
    }

    private func handshake(settings: SSHClientSettings, seconds: Int, cloudflareTarget: String?, accessToken: String?) async throws -> SSHClient {
        let waiter = SSHHandshakeWaiter()
        let backend = self.backend
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                guard waiter.install(continuation) else { return }
                let operation = Task {
                    do {
                        try Task.checkCancellation()
                        let client: SSHClient
                        if let cloudflareTarget, let accessToken {
                            guard let backend = backend as? any SSHCloudflareConnectionBackend else {
                                throw SSHFailure.cloudflareRelayUnavailable
                            }
                            client = try await backend.connect(settings: settings, target: cloudflareTarget, accessToken: accessToken)
                        } else {
                            client = try await backend.connect(settings: settings)
                        }
                        // Future-based libraries may finish after cancellation. Never leak or
                        // publish that late client into a replacement session.
                        if !waiter.finish(.success(client)) { try? await client.close() }
                    } catch { _ = waiter.finish(.failure(error)) }
                }
                waiter.setOperation(operation)
                let deadline = Task {
                    do { try await Task.sleep(nanoseconds: UInt64(seconds) * 1_000_000_000) }
                    catch { return }
                    _ = waiter.finish(.failure(SSHFailure.connectionTimedOut))
                }
                waiter.setDeadline(deadline)
            }
        } onCancel: {
            _ = waiter.finish(.failure(CancellationError()))
        }
    }
}

/// The lock protects the continuation and task handles; no callback runs while it is held.
/// Cancellation returns immediately even when a third-party future ignores Task cancellation.
private final class SSHHandshakeWaiter: @unchecked Sendable {
    private let lock = NSLock()
    private var finished = false
    private var earlyFailure: Error?
    private var continuation: CheckedContinuation<SSHClient, Error>?
    private var operation: Task<Void, Never>?
    private var deadline: Task<Void, Never>?

    func install(_ value: CheckedContinuation<SSHClient, Error>) -> Bool {
        lock.lock()
        if finished {
            let error = earlyFailure ?? CancellationError()
            lock.unlock()
            value.resume(throwing: error)
            return false
        }
        continuation = value
        lock.unlock()
        return true
    }

    func setOperation(_ value: Task<Void, Never>) {
        lock.lock()
        let cancel = finished
        if !cancel { operation = value }
        lock.unlock()
        if cancel { value.cancel() }
    }

    func setDeadline(_ value: Task<Void, Never>) {
        lock.lock()
        let cancel = finished
        if !cancel { deadline = value }
        lock.unlock()
        if cancel { value.cancel() }
    }

    @discardableResult func finish(_ result: Result<SSHClient, Error>) -> Bool {
        lock.lock()
        guard !finished else { lock.unlock(); return false }
        finished = true
        if case .failure(let error) = result { earlyFailure = error }
        let continuation = self.continuation
        let operation = self.operation
        let deadline = self.deadline
        self.continuation = nil
        self.operation = nil
        self.deadline = nil
        lock.unlock()
        deadline?.cancel()
        if case .failure = result { operation?.cancel() }
        continuation?.resume(with: result)
        return true
    }
}

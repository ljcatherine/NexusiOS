import Foundation
import Citadel
import Crypto
import NIO
import NIOSSH
import NexusCore

/// One transport per terminal tab. All client/writer ownership is confined to this actor.
public actor SSHTransport {
    private var client: SSHClient?
    private var writer: TTYStdinWriter?
    private var generation = UUID()
    private var columns = 80
    private var rows = 24
    private let pipeline: SSHConnectionPipeline
    public init(pipeline: SSHConnectionPipeline = .shared) { self.pipeline = pipeline }

    public static func credentialAccount(_ device: Device) -> String { "credential:" + device.id.uuidString }
    /// Validate locally supplied authentication material before the app stores it in Keychain.
    public static func validateCredential(for device: Device, credential: Credential) throws {
        _ = try authentication(device: device, credential: credential)
    }

    static func authentication(device: Device, credential: Credential) throws -> SSHAuthenticationMethod {
        guard device.authentication == .ed25519 else { throw SSHFailure.missingCredential }
        guard credential.passphrase.utf8.count <= 4_096 else { throw SSHFailure.invalidPrivateKey }
        let secret = try SSHPrivateKeyFile.normalize(credential.secret)
        let passphrase = credential.passphrase.isEmpty ? nil : Data(credential.passphrase.utf8)
        do {
            return .ed25519(username: device.username,
                privateKey: try Curve25519.Signing.PrivateKey(sshEd25519: secret, decryptionKey: passphrase))
        } catch { throw SSHFailure.invalidPrivateKey }
    }

    public func run(device: Device, endpoint: Endpoint, secrets: any SecretStore, timeout: Int,
                    onStage: @escaping @Sendable (SSHConnectionStage) async -> Void = { _ in },
                    onConnected: @escaping @Sendable () async -> Void,
                    onOutput: @escaping @Sendable (Data) async -> Void) async throws {
        await disconnect()
        let attempt = UUID(); generation = attempt
        let connected = try await pipeline.connect(device: device, endpoint: endpoint,
            secrets: secrets, timeout: timeout, onStage: onStage)
        guard generation == attempt, !Task.isCancelled else { try? await connected.close(); throw CancellationError() }
        client = connected
        var reachedEOF = false
        do {
            await onStage(.openingShell)
            guard generation == attempt, !Task.isCancelled else { throw CancellationError() }
            let request = SSHChannelRequestEvent.PseudoTerminalRequest(wantReply: true, term: "xterm-256color",
                terminalCharacterWidth: columns, terminalRowHeight: rows, terminalPixelWidth: 0,
                terminalPixelHeight: 0, terminalModes: .init([:]))
            try await connected.withPTY(request) { inbound, outbound in
                try await self.setWriter(outbound, attempt: attempt)
                guard self.isCurrent(attempt) else { throw CancellationError() }
                await onStage(.connected)
                guard self.isCurrent(attempt) else { throw CancellationError() }
                await onConnected()
                guard self.isCurrent(attempt) else { throw CancellationError() }
                for try await output in inbound {
                    try Task.checkCancellation()
                    switch output {
                    case .stdout(let bytes), .stderr(let bytes):
                        await onOutput(Data(bytes.readableBytesView))
                    }
                }
                reachedEOF = true
            }
        } catch {
            await disconnectIfCurrent(attempt)
            // OpenSSH can close its channel before Citadel's withPTY cleanup closes it again.
            // Suppress only this known cleanup error after a successfully exhausted output stream.
            if reachedEOF, let channelError = error as? ChannelError, case .alreadyClosed = channelError { return }
            throw error
        }
        await disconnectIfCurrent(attempt)
    }

    /// Fetch one bounded, read-only Linux metrics snapshot over the verified SSH connection.
    public func fetchMetrics(device: Device, endpoint: Endpoint, secrets: any SecretStore,
                             timeout: Int) async throws -> HostMetricsSnapshot {
        await disconnect()
        let attempt = UUID(); generation = attempt
        let connected = try await pipeline.connect(device: device, endpoint: endpoint,
            secrets: secrets, timeout: timeout)
        guard generation == attempt, !Task.isCancelled else {
            try? await connected.close()
            throw CancellationError()
        }
        client = connected

        let buffer: ByteBuffer
        do {
            buffer = try await connected.executeCommand(HostMetricsCommand.snapshot(timeout: timeout),
                maxResponseSize: 32 * 1024)
        } catch let commandFailure as SSHClient.CommandFailed
            where commandFailure.exitCode == 124 || commandFailure.exitCode == 137 {
            await disconnectIfCurrent(attempt)
            throw SSHFailure.metricsCommandTimedOut
        } catch {
            await disconnectIfCurrent(attempt)
            if Task.isCancelled { throw CancellationError() }
            throw SSHFailure.metricsCommandFailed
        }
        await disconnectIfCurrent(attempt)
        let output = String(decoding: buffer.readableBytesView, as: UTF8.self)
        do {
            return try HostMetricsParser.parse(output)
        } catch {
            throw SSHFailure.invalidMetricsResponse
        }
    }

    private func isCurrent(_ attempt: UUID) -> Bool { generation == attempt && !Task.isCancelled }
    private func setWriter(_ writer: TTYStdinWriter, attempt: UUID) async throws {
        guard generation == attempt, !Task.isCancelled else { throw CancellationError() }
        self.writer = writer
        try await writer.changeSize(cols: columns, rows: rows, pixelWidth: 0, pixelHeight: 0)
        guard generation == attempt, !Task.isCancelled else { throw CancellationError() }
    }
    public func send(_ data: Data) async throws {
        guard let writer else { throw SSHFailure.notConnected }
        try await writer.write(ByteBuffer(bytes: data))
    }
    public func resize(columns: Int, rows: Int) async throws {
        self.columns = max(2, columns); self.rows = max(2, rows)
        try await writer?.changeSize(cols: self.columns, rows: self.rows, pixelWidth: 0, pixelHeight: 0)
    }
    private func disconnectIfCurrent(_ attempt: UUID) async {
        if generation == attempt { await disconnect() }
    }
    public func disconnect() async {
        generation = UUID()
        let old = client; client = nil; writer = nil
        try? await old?.close()
    }
}

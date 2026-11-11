import Foundation
import Citadel
import NIO
import NIOSSH
import NexusCore

public struct CommandResult: Sendable {
    public let output: String
    public let exitCode: Int
    public let outputTruncated: Bool
    public let timedOut: Bool
}

public actor CommandTransport {
    private var activeClients: [UUID: SSHClient] = [:]
    private var connectionGeneration = 0

    private let pipeline: SSHConnectionPipeline
    public init(pipeline: SSHConnectionPipeline = .shared) { self.pipeline = pipeline }

    public func disconnectAll() async {
        connectionGeneration &+= 1
        let clients = Array(activeClients.values)
        activeClients.removeAll()
        for client in clients { try? await client.close() }
    }

    /// Runs a user-previewed command on exactly one pinned endpoint. It never retries side effects.
    public func run(_ command: String, useSudo: Bool, device: Device, endpoint: Endpoint,
                    secrets: any SecretStore, timeout: Int) async throws -> CommandResult {
        try device.validate(); try endpoint.validate()
        guard !command.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              command.utf8.count <= 4096, !command.contains("\0") else {
            throw CommandTransportError.invalidCommand
        }
        let attemptGeneration = connectionGeneration
        let client = try await pipeline.connect(device: device, endpoint: endpoint,
            secrets: secrets, timeout: timeout)
        guard connectionGeneration == attemptGeneration, !Task.isCancelled else {
            try? await client.close()
            throw CancellationError()
        }
        let operationID = UUID()
        activeClients[operationID] = client

        let inner = "sh -c \(Shell.quote(command))"
        let operation = useSudo ? "sudo -n \(inner)" : inner
        let bounded = Self.bounded(operation, timeout: timeout)
        var stdout = Data()
        var stderr = Data()
        var outputTruncated = false
        var exitCode = 0
        do {
            let stream = try await client.executeCommandStream(bounded)
            for try await chunk in stream {
                let buffer: ByteBuffer
                let isStandardError: Bool
                switch chunk {
                case .stdout(let value): buffer = value; isStandardError = false
                case .stderr(let value): buffer = value; isStandardError = true
                }
                let remaining = max(0, 64 * 1024 - stdout.count - stderr.count)
                let bytes = buffer.readableBytesView
                let count = min(remaining, bytes.count)
                if isStandardError { stderr.append(contentsOf: bytes.prefix(count)) }
                else { stdout.append(contentsOf: bytes.prefix(count)) }
                if count < bytes.count { outputTruncated = true }
            }
        } catch let failure as SSHClient.CommandFailed {
            exitCode = failure.exitCode
        } catch {
            activeClients[operationID] = nil
            try? await client.close()
            if Task.isCancelled || connectionGeneration != attemptGeneration { throw CancellationError() }
            throw error
        }
        guard connectionGeneration == attemptGeneration, !Task.isCancelled else {
            activeClients[operationID] = nil
            try? await client.close()
            throw CancellationError()
        }
        activeClients[operationID] = nil
        try? await client.close()
        let stdoutText = String(decoding: stdout, as: UTF8.self)
        let stderrText = String(decoding: stderr, as: UTF8.self)
        let combinedOutput = stderrText.isEmpty ? stdoutText :
            [stdoutText, "[stderr]", stderrText].filter { !$0.isEmpty }.joined(separator: "\n")
        let outputData = Data(combinedOutput.utf8)
        outputTruncated = outputTruncated || outputData.count > 64 * 1024
        let output = String(decoding: outputData.prefix(64 * 1024), as: UTF8.self)
        return CommandResult(output: output, exitCode: exitCode,
            outputTruncated: outputTruncated, timedOut: exitCode == 124 || exitCode == 137)
    }

    private static func bounded(_ command: String, timeout: Int) -> String {
        RemoteCommandTimeout.wrap(command, timeout: timeout, maximum: 120, errorPrefix: "nexus_command_error")
    }
}

public enum CommandTransportError: LocalizedError {
    case invalidCommand
    case commandTimedOut
    case commandFailed(exitCode: Int)

    public var errorDescription: String? {
        switch self {
        case .invalidCommand: return "This recipe produced an empty or oversized command."
        case .commandTimedOut: return "The remote command exceeded the configured timeout."
        case .commandFailed(let code): return "The remote command exited with status \(code)."
        }
    }
}

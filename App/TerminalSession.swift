import SwiftUI
import UIKit
import SwiftTerm
import OSLog
import NexusCore
import NexusSSH

@MainActor @Observable
final class TerminalSession: Identifiable {
    private static let logger = Logger(
        subsystem: Bundle.main.bundleIdentifier ?? "com.ljcatherine.Nexus",
        category: "SSH"
    )
    let id = UUID()
    let device: Device
    var state: SessionState = .disconnected
    var endpoint: Endpoint?
    var error: String?
    var failureDiagnostic: String?
    var challenge: HostKeyChallenge?
    var connectionStage: SSHConnectionStage?
    var failureStage: SSHConnectionStage?
    var title = "Shell"
    let terminal = SwiftTerm.TerminalView(frame: .zero)
    private let transport = SSHTransport()
    private let secrets: KeychainStore
    private let timeout: Int
    private let demoMode: Bool
    private var task: Task<Void, Never>?
    private var inputTail: Task<Void, Never>?
    private var attempt = UUID()
    private var resizeTask: Task<Void, Never>?
    init(device: Device, secrets: KeychainStore, timeout: Int, demoMode: Bool = false) {
        self.device = device; self.secrets = secrets; self.timeout = timeout; self.demoMode = demoMode
        terminal.nativeBackgroundColor = .systemBackground
        terminal.nativeForegroundColor = .label
    }
    func connect(endpoint selected: Endpoint? = nil) {
        guard task == nil else { return }
        if demoMode {
            endpoint = selected ?? device.orderedEndpoints.first
            error = nil
            challenge = nil
            failureStage = nil
            connectionStage = .connected
            state = .connected
            terminal.feed(byteArray: ArraySlice(Array("Nexus interactive shell · simulated data only\r\nNo SSH connection or command execution occurs in this preview.\r\n$ ".utf8)))
            return
        }
        let token = UUID(); attempt = token
        error = nil; failureDiagnostic = nil; challenge = nil; failureStage = nil
        connectionStage = .checkingProfile; state = .connecting
        Self.logger.info("SSH attempt started")
        task = Task { [weak self] in
            guard let self else { return }
            let candidates = selected.map { [$0] } ?? device.orderedEndpoints
            for candidate in candidates {
                guard !Task.isCancelled, attempt == token else { return }
                endpoint = candidate
                do {
                    try await transport.run(device: device, endpoint: candidate, secrets: secrets, timeout: timeout,
                        onStage: { [weak self] stage in
                            await self?.updateStage(stage, token: token)
                        },
                        onConnected: { [weak self] in
                            await self?.didConnect(token)
                        }, onOutput: { [weak self] data in
                            await self?.receive(data, token: token)
                        })
                    guard attempt == token else { return }
                    state = .disconnected; task = nil; return
                } catch let value as HostKeyChallenge {
                    guard attempt == token else { return }
                    Self.logger.notice("SSH stopped for explicit host-key verification; changed key: \(value.changed, privacy: .public)")
                    challenge = value; connectionStage = nil; state = .verifyingHost; task = nil; return
                } catch is CancellationError {
                    guard attempt == token else { return }
                    Self.logger.info("SSH attempt cancelled")
                    state = .disconnected; task = nil; connectionStage = nil; return
                }
                catch {
                    guard attempt == token else { return }
                    Self.logger.error("SSH attempt failed with error type \(String(reflecting: type(of: error)), privacy: .public)")
                    self.error = error.localizedDescription
                    let classifiedFailure: SSHFailure?
                    if let handshakeFailure = error as? SSHHandshakeFailure {
                        classifiedFailure = handshakeFailure.failure
                        failureDiagnostic = handshakeFailure.diagnostic
                    } else {
                        classifiedFailure = error as? SSHFailure
                        failureDiagnostic = SSHDiagnosticFormatter.describe(error)
                    }
                    failureStage = connectionStage
                    if let failure = classifiedFailure, !failure.allowsEndpointFallback { break }
                    // Only route/connect failures can try a lower-priority endpoint. Authentication,
                    // identity, key and protocol failures must be visible without another attempt.
                }
            }
            guard attempt == token else { return }
            connectionStage = nil; state = .failed; task = nil
        }
    }
    private func didConnect(_ token: UUID) {
        guard attempt == token else { return }
        Self.logger.info("SSH authenticated and PTY is ready")
        error = nil; connectionStage = .connected; state = .connected
        if device.useTmux { send(Data(Shell.tmux(sessionID: id).utf8)) }
    }
    private func updateStage(_ stage: SSHConnectionStage, token: UUID) {
        guard attempt == token else { return }
        Self.logger.debug("SSH progress stage: \(stage.rawValue, privacy: .public)")
        connectionStage = stage
    }
    private func receive(_ data: Data, token: UUID) {
        guard attempt == token else { return }
        terminal.feed(byteArray: ArraySlice(data))
    }
    func acceptHost() {
        guard let challenge else { return }
        do {
            try HostKeyVerifier.approve(challenge, secrets: secrets)
            self.challenge = nil; connectionStage = .connecting; connect(endpoint: challenge.endpoint)
        } catch { self.error = error.localizedDescription; state = .failed; self.challenge = nil }
    }
    func replaceChangedHostKey(confirmedFingerprint: String) {
        guard let challenge, challenge.changed else { return }
        do {
            try HostKeyVerifier.replace(challenge, confirmedFingerprint: confirmedFingerprint, secrets: secrets)
            self.challenge = nil; connectionStage = .connecting
            connect(endpoint: challenge.endpoint)
        } catch {
            self.error = error.localizedDescription
            state = .failed
            self.challenge = nil
        }
    }
    func rejectHost() { challenge = nil; connectionStage = nil; state = .disconnected }
    func send(_ data: Data) {
        guard state == .connected else { return }
        if demoMode {
            let submitted = String(decoding: data, as: UTF8.self)
                .replacingOccurrences(of: "\r", with: "")
                .trimmingCharacters(in: .whitespacesAndNewlines)
            guard !submitted.isEmpty else { return }
            let response = "\r\n\u{001B}[2mPreview only · no command was sent\u{001B}[0m\r\n$ "
            terminal.feed(byteArray: ArraySlice(Array(response.utf8)))
            return
        }
        let previous = inputTail
        let token = attempt
        inputTail = Task { [weak self] in
            await previous?.value
            guard let self, !Task.isCancelled, attempt == token else { return }
            do { try await transport.send(data) }
            catch { self.error = "Terminal input failed. Reconnect the session."; disconnect() }
        }
    }
    func resize(columns: Int, rows: Int) {
        guard !demoMode else { return }
        resizeTask?.cancel()
        resizeTask = Task { [weak self] in
            try? await Task.sleep(for: .milliseconds(80))
            guard let self, !Task.isCancelled else { return }
            do { try await transport.resize(columns: columns, rows: rows) }
            catch { self.error = "The server rejected terminal resizing." }
        }
    }
    func disconnect() {
        attempt = UUID(); task?.cancel(); task = nil; inputTail?.cancel(); inputTail = nil
        resizeTask?.cancel(); challenge = nil; connectionStage = nil; state = .disconnected
        // Keep task non-nil until transport closure completes, preventing a reconnect/close race.
        guard !demoMode else { return }
        task = Task { [weak self] in
            guard let self else { return }; await transport.disconnect(); task = nil
        }
    }
}

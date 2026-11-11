import Foundation
import Crypto
import NIO
import NIOSSH
import NexusCore

public struct HostKeyChallenge: Error, Identifiable, Sendable {
    public var id: String { endpoint.authority }
    public let endpoint: Endpoint
    public let publicKey: String
    public let fingerprint: String
    public let changed: Bool
    public let previousPublicKey: String?
    public let previousFingerprint: String?
}

/// Reject first contact, ask outside the SSH handshake, then reconnect after explicit approval.
/// Citadel has a ten-second login deadline, which must never time-limit a human trust decision.
public final class HostKeyVerifier: NIOSSHClientServerAuthenticationDelegate, @unchecked Sendable {
    private let endpoint: Endpoint
    private let secrets: any SecretStore
    private let lock = NSLock()
    private var captured: HostKeyChallenge?
    private var acceptedPinnedKey = false
    public init(endpoint: Endpoint, secrets: any SecretStore) { self.endpoint = endpoint; self.secrets = secrets }
    public var challenge: HostKeyChallenge? {
        lock.lock(); defer { lock.unlock() }; return captured
    }
    public var didAcceptPinnedHostKey: Bool {
        lock.lock(); defer { lock.unlock() }; return acceptedPinnedKey
    }
    public static func fingerprint(_ publicKey: String) throws -> String {
        let fields = publicKey.split(separator: " ")
        guard fields.count >= 2, let blob = Data(base64Encoded: String(fields[1])) else { throw SSHFailure.invalidHostKey }
        return "SHA256:" + Data(SHA256.hash(data: blob)).base64EncodedString().replacingOccurrences(of: "=", with: "")
    }
    public static func account(_ endpoint: Endpoint) -> String { "hostkey:" + endpoint.authority }
    private static func storedKey(_ endpoint: Endpoint, secrets: any SecretStore) throws -> String? {
        guard let data = try secrets.read(account(endpoint)) else { return nil }
        guard let value = String(data: data, encoding: .utf8), (try? NIOSSHPublicKey(openSSHPublicKey: value)) != nil else {
            throw SSHFailure.invalidHostKey
        }
        return value
    }
    public func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
        do {
            let presented = String(openSSHPublicKey: hostKey)
            let stored = try Self.storedKey(endpoint, secrets: secrets)
            let decision = HostTrust.evaluate(stored: stored, presented: presented)
            if decision == .trusted {
                lock.lock(); acceptedPinnedKey = true; lock.unlock()
                validationCompletePromise.succeed(()); return
            }
            let challenge = HostKeyChallenge(endpoint: endpoint, publicKey: presented,
                fingerprint: try Self.fingerprint(presented), changed: decision == .changed,
                previousPublicKey: stored,
                previousFingerprint: try stored.map(Self.fingerprint))
            lock.lock(); captured = challenge; lock.unlock()
            validationCompletePromise.fail(challenge)
        } catch { validationCompletePromise.fail(error) }
    }
    public static func approve(_ challenge: HostKeyChallenge, secrets: any SecretStore) throws {
        guard !challenge.changed else { throw SSHFailure.changedHostKey }
        // Re-check to avoid overwriting a pin changed by another simultaneous session.
        let current = try storedKey(challenge.endpoint, secrets: secrets)
        guard HostTrust.evaluate(stored: current, presented: challenge.publicKey) != .changed else { throw SSHFailure.changedHostKey }
        try secrets.write(Data(challenge.publicKey.utf8), account: account(challenge.endpoint))
    }

    /// Replace a changed pin only after the user compares and types the new fingerprint out of band.
    public static func replace(_ challenge: HostKeyChallenge, confirmedFingerprint: String,
                              secrets: any SecretStore) throws {
        guard challenge.changed,
              let previousPublicKey = challenge.previousPublicKey,
              confirmedFingerprint == challenge.fingerprint else {
            throw SSHFailure.fingerprintConfirmationMismatch
        }
        let current = try storedKey(challenge.endpoint, secrets: secrets)
        guard current == previousPublicKey else { throw SSHFailure.changedHostKey }
        try secrets.write(Data(challenge.publicKey.utf8), account: account(challenge.endpoint))
    }
}

public enum SSHFailure: LocalizedError, Equatable, Sendable {
    case missingCredential, exampleEndpoint, invalidHostKey, changedHostKey, fingerprintConfirmationMismatch
    case connectionFailed, connectionTimedOut, endpointNameResolutionFailed, connectionRefused, networkUnreachable
    case trustedEndpointHandshakeFailed
    case authenticationRejected, publicKeyAuthenticationUnavailable
    case invalidCredentialRecord, metricsCommandFailed, metricsCommandTimedOut, invalidMetricsResponse
    case notConnected, invalidPrivateKey
    case cloudflareSignInRequired, cloudflareRelayUnavailable
    /// Enum case identifiers are static source labels and safe to include in diagnostics.
    var diagnosticName: String { String(describing: self) }

    public var errorDescription: String? {
        switch self {
        case .missingCredential: return "Choose an Ed25519 OpenSSH private key in this device's connection settings."
        case .exampleEndpoint: return "This is an example address. Edit the device profile with its real hostname or IP address before connecting."
        case .invalidHostKey: return "The server supplied an invalid SSH host key."
        case .changedHostKey: return "HOST KEY CHANGED. Connection blocked. Verify the new fingerprint outside Nexus before replacing the saved pin."
        case .fingerprintConfirmationMismatch: return "The typed fingerprint does not match the new server key. The saved host key was not changed."
        case .connectionFailed: return "SSH connection failed. Check VPN/LAN connectivity, port, username, and authentication."
        case .connectionTimedOut: return "The SSH handshake timed out. Check that the endpoint is reachable and retry."
        case .endpointNameResolutionFailed: return "Nexus couldn't resolve this endpoint name. Check the spelling and connect Tailscale if this is a Tailscale address."
        case .connectionRefused: return "Nexus reached the endpoint, but its SSH port refused the connection. Check the port and confirm SSH is running on that device."
        case .networkUnreachable: return "Nexus has no route to this endpoint. Connect to the same LAN or Tailscale network, then retry."
        case .trustedEndpointHandshakeFailed: return "The verified server could not complete SSH authentication. Check its credentials and SSH policy. Nexus did not try another endpoint."
        case .authenticationRejected: return "The SSH server rejected this key. Check the saved username and whether its matching public key is installed for that account on the server."
        case .publicKeyAuthenticationUnavailable: return "The SSH server did not offer public-key authentication. Check that the server allows key-based SSH login."
        case .invalidCredentialRecord: return "The saved SSH key record is invalid. Re-import the private key in connection settings."
        case .metricsCommandFailed: return "The server connected, but its read-only status command failed. Check that it is a supported Linux host."
        case .metricsCommandTimedOut: return "The server's read-only status command exceeded the configured timeout. The SSH connection was closed; refresh to retry."
        case .invalidMetricsResponse: return "The server returned an invalid status response. No metrics were displayed."
        case .notConnected: return "The terminal is disconnected. Reconnect before sending input."
        case .invalidPrivateKey: return "Nexus could not unlock this Ed25519 OpenSSH private key. Check that it is an OpenSSH private key and that its passphrase is correct."
        case .cloudflareSignInRequired: return "Sign in to the Nexus Cloudflare API connection before connecting to this device."
        case .cloudflareRelayUnavailable: return "The Cloudflare SSH relay is unavailable. Check Cloudflare Access and the Debian gateway."
        }
    }

    public var allowsEndpointFallback: Bool {
        switch self {
        case .connectionFailed, .connectionTimedOut, .endpointNameResolutionFailed,
             .connectionRefused, .networkUnreachable: return true
        default: return false
        }
    }
}

import Citadel

/// Centralizes the Citadel connector used by terminal, metrics, services, and SFTP.
public enum SSHClientConnector {
    public static func connect(to settings: SSHClientSettings) async throws -> SSHClient {
        try await SSHClient.connect(to: settings)
    }
}

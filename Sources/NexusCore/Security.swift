import Foundation

public protocol SecretStore: Sendable {
    func read(_ account: String) throws -> Data?
    func write(_ data: Data, account: String) throws
    func delete(_ account: String) throws
}

public struct Credential: Codable, Sendable {
    public var secret: String
    public var passphrase: String
    public init(secret: String, passphrase: String = "") { self.secret = secret; self.passphrase = passphrase }
}

public enum HostTrustDecision: Equatable { case trusted, confirmationRequired, changed }
public enum HostTrust {
    public static func evaluate(stored: String?, presented: String) -> HostTrustDecision {
        guard let stored else { return .confirmationRequired }
        return stored == presented ? .trusted : .changed
    }
}

public enum SessionState: String, Sendable {
    case disconnected, connecting, verifyingHost, connected, failed
}

public enum Shell {
    public static func quote(_ argument: String) -> String {
        "'" + argument.replacingOccurrences(of: "'", with: "'\"'\"'") + "'"
    }
    public static func tmux(sessionID: UUID) -> String {
        "tmux new-session -A -s " + quote("nexus-" + sessionID.uuidString.lowercased()) + "\r"
    }
}

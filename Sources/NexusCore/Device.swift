import Foundation

public enum EndpointKind: String, Codable, CaseIterable, Sendable { case lan, tailscale, cloudflare }
public enum AuthenticationKind: Sendable, Codable {
    case ed25519, legacyPassword, legacyRSA

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let storedValue = try container.decode(String.self)
        switch storedValue {
        case "ed25519": self = .ed25519
        case "password": self = .legacyPassword
        case "rsa": self = .legacyRSA
        default:
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Unsupported SSH authentication type.")
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .ed25519, .legacyPassword, .legacyRSA: try container.encode("ed25519")
        }
    }
}

public struct Endpoint: Codable, Hashable, Identifiable, Sendable {
    public var id: UUID
    public var host: String
    public var port: Int
    public var kind: EndpointKind
    public var priority: Int
    public var relayTarget: String?
    public init(id: UUID = UUID(), host: String, port: Int = 22, kind: EndpointKind = .lan, priority: Int = 0,
                relayTarget: String? = nil) {
        self.id = id; self.host = host; self.port = port; self.kind = kind; self.priority = priority
        self.relayTarget = relayTarget
    }
    public var authority: String { "[\(host.lowercased())]:\(port)" }
    /// Reserved documentation addresses must never be treated as real devices.
    public var isExampleAddress: Bool {
        let normalizedHost = host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        return normalizedHost == "example.invalid" || normalizedHost.hasSuffix(".example.invalid")
    }
    public func validate() throws {
        guard !host.isEmpty, host.count <= 253,
              !host.contains(where: { $0.isWhitespace }),
              host.unicodeScalars.allSatisfy({ CharacterSet.alphanumerics.union(CharacterSet(charactersIn: ".:-_%")).contains($0) }),
              (1...65535).contains(port) else { throw ConfigurationError.invalidEndpoint }
        if kind == .cloudflare {
            guard port == 443, relayTarget == "nixos" || relayTarget == "debian",
                  !host.contains(":"), !host.contains("/") else { throw ConfigurationError.invalidEndpoint }
        }
    }
}

public struct Device: Codable, Hashable, Identifiable, Sendable {
    public var id: UUID
    public var name: String
    public var username: String
    public var endpoints: [Endpoint]
    public var authentication: AuthenticationKind
    public var useTmux: Bool
    public init(id: UUID = UUID(), name: String, username: String, endpoints: [Endpoint],
                authentication: AuthenticationKind = .ed25519, useTmux: Bool = false) {
        self.id = id; self.name = name; self.username = username; self.endpoints = endpoints
        self.authentication = authentication; self.useTmux = useTmux
    }
    public var orderedEndpoints: [Endpoint] {
        endpoints.enumerated().sorted { ($0.element.priority, $0.offset) < ($1.element.priority, $1.offset) }.map(\.element)
    }
    public func validate() throws {
        guard !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              !username.isEmpty, !username.contains(where: { $0.isWhitespace || $0.isNewline }),
              !endpoints.isEmpty,
              Set(endpoints.map(\.authority)).count == endpoints.count,
              Set(endpoints.map(\.id)).count == endpoints.count else {
            throw ConfigurationError.invalidDevice
        }
        try endpoints.forEach { try $0.validate() }
    }
    /// First-launch suggestions from the build's deployment configuration; empty by default.
    public static var suggestions: [Device] { DeploymentConfiguration.current.suggestedDevices }
}

public enum ConfigurationError: LocalizedError {
    case invalidEndpoint, invalidDevice, unsupportedVersion
    public var errorDescription: String? {
        switch self {
        case .invalidEndpoint: return "Enter a hostname or IP address and a port from 1 to 65535."
        case .invalidDevice: return "A device needs a name, username, and unique connection endpoints."
        case .unsupportedVersion: return "This configuration version is not supported."
        }
    }
}

public struct Configuration: Codable, Sendable {
    public var version: Int = 1
    public var devices: [Device]
    public init(devices: [Device]) { self.devices = devices }
    public static func decode(_ data: Data) throws -> Configuration {
        let value = try JSONDecoder().decode(Self.self, from: data)
        guard value.version == 1 else { throw ConfigurationError.unsupportedVersion }
        guard Set(value.devices.map(\.id)).count == value.devices.count else { throw ConfigurationError.invalidDevice }
        try value.devices.forEach { try $0.validate() }
        return value
    }
}

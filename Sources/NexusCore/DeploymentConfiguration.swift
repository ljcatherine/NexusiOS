import Foundation

/// Values that belong to one person's deployment rather than to Nexus itself:
/// the Cloudflare Worker hostname, its Access team issuer and public OAuth
/// client ID, a default AI endpoint, and suggested relay devices.
///
/// The public source ships none of them. A build supplies them through
/// Info.plist keys (see `docs/CONFIGURATION.md`); when a key is missing or
/// empty, the matching feature is simply not preconfigured.
public struct DeploymentConfiguration: Sendable, Equatable {
    public struct RelayDevice: Sendable, Equatable {
        public var name: String
        public var username: String
        public var target: String
        public init(name: String, username: String, target: String) {
            self.name = name; self.username = username; self.target = target
        }
    }

    public enum Key {
        public static let gatewayHost = "NexusGatewayHost"
        public static let accessIssuer = "NexusAccessIssuer"
        public static let accessClientID = "NexusAccessClientID"
        public static let defaultAIEndpoint = "NexusDefaultAIEndpoint"
        public static let relayDevices = "NexusRelayDevices"
    }

    /// Hostname of the Access-protected Worker, for example `nexus.example.workers.dev`.
    public var gatewayHost: String?
    /// Cloudflare Access team issuer, for example `https://team.cloudflareaccess.com`.
    public var accessIssuer: String?
    /// Public Managed OAuth client ID. It is an identifier, not a secret.
    public var accessClientID: String?
    /// Prefilled base URL for a new PS5LM Plus connection.
    public var defaultAIEndpoint: String?
    /// Devices suggested on first launch, each routed through the Worker relay.
    public var relayDevices: [RelayDevice]

    public init(gatewayHost: String? = nil, accessIssuer: String? = nil, accessClientID: String? = nil,
                defaultAIEndpoint: String? = nil, relayDevices: [RelayDevice] = []) {
        let host = Self.clean(gatewayHost)?.lowercased()
        self.gatewayHost = host
        self.accessIssuer = Self.clean(accessIssuer)
        self.accessClientID = Self.clean(accessClientID)
        self.defaultAIEndpoint = Self.clean(defaultAIEndpoint)
        self.relayDevices = host == nil ? [] : relayDevices.filter {
            Self.clean($0.name) != nil && Self.clean($0.username) != nil && Self.clean($0.target) != nil
        }
    }

    public init(infoDictionary: [String: Any]) {
        let entries = infoDictionary[Key.relayDevices] as? [[String: Any]] ?? []
        let relays = entries.compactMap { entry -> RelayDevice? in
            guard let name = entry["name"] as? String, let username = entry["username"] as? String,
                  let target = entry["target"] as? String else { return nil }
            return RelayDevice(name: name, username: username, target: target)
        }
        self.init(gatewayHost: infoDictionary[Key.gatewayHost] as? String,
                  accessIssuer: infoDictionary[Key.accessIssuer] as? String,
                  accessClientID: infoDictionary[Key.accessClientID] as? String,
                  defaultAIEndpoint: infoDictionary[Key.defaultAIEndpoint] as? String,
                  relayDevices: relays)
    }

    public static let current = DeploymentConfiguration(infoDictionary: Bundle.main.infoDictionary ?? [:])

    /// `https://<gatewayHost>` when a gateway is configured.
    public var gatewayOrigin: String? { gatewayHost.map { "https://\($0)" } }

    /// True when the Worker, Access issuer and OAuth client are all configured.
    public var hasManagedAccessGateway: Bool {
        gatewayHost != nil && accessIssuer != nil && accessClientID != nil
    }

    /// The relay alias for a device whose SSH username matches a configured relay device.
    public func relayTarget(forUsername username: String) -> String? {
        let normalized = username.lowercased()
        return relayDevices.first { $0.username.lowercased() == normalized }?.target
    }

    public var suggestedDevices: [Device] {
        guard let gatewayHost else { return [] }
        return relayDevices.map { relay in
            Device(name: relay.name, username: relay.username, endpoints: [.init(
                host: gatewayHost, port: 443, kind: .cloudflare, relayTarget: relay.target)])
        }
    }

    private static func clean(_ value: String?) -> String? {
        guard let trimmed = value?.trimmingCharacters(in: .whitespacesAndNewlines), !trimmed.isEmpty else { return nil }
        return trimmed
    }
}

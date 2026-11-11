import Foundation

/// The HTTPS scheme, host, and effective port allowed for panel web navigation.
public struct HTTPSOrigin: Equatable, Sendable {
    private let scheme: String
    private let host: String
    private let port: Int

    public init(url: URL) {
        scheme = (url.scheme ?? "").lowercased()
        host = (url.host ?? "").lowercased()
        port = url.port ?? 443
    }

    public func allows(_ url: URL) -> Bool {
        url.scheme?.lowercased() == "https"
            && !host.isEmpty
            && url.host?.caseInsensitiveCompare(host) == .orderedSame
            && (url.port ?? 443) == port
            && url.user == nil
            && url.password == nil
    }
}

/// A private Minecraft panel address that cannot point to a placeholder or embed credentials.
public struct MinecraftPanelAddress: Equatable, Sendable {
    public let url: URL
    public let origin: HTTPSOrigin

    public init(_ value: String) throws {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let url = URL(string: trimmed),
              url.scheme?.lowercased() == "https",
              let host = url.host, !host.isEmpty,
              url.user == nil, url.password == nil,
              url.query == nil, url.fragment == nil,
              url.port.map({ (1...65535).contains($0) }) ?? true else {
            throw MinecraftPanelAddressError.invalidAddress
        }
        let normalizedHost = host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        guard normalizedHost != "example.invalid",
              !normalizedHost.hasSuffix(".example.invalid") else {
            throw MinecraftPanelAddressError.invalidAddress
        }
        self.url = url
        origin = HTTPSOrigin(url: url)
    }
}

public enum MinecraftPanelAddressError: Error, Equatable, Sendable {
    case invalidAddress
}

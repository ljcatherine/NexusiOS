import Foundation
import Darwin
import NexusCore

typealias EndpointDNSProbeResult = DNSResolutionResult

extension DNSResolutionResult {
    var summary: String {
        switch self {
        case .resolved(let addresses, let milliseconds):
            return "Resolved \(addresses.count) address(es) · \(milliseconds) ms"
        case .failed(let reason):
            return "Resolution failed · \(reason)"
        }
    }
}

/// Resolves a saved endpoint's host name only. It does not open a socket or verify a server.
enum EndpointDNSProbe {
    static func resolve(_ endpoint: Endpoint, timeout: TimeInterval = 8) async -> EndpointDNSProbeResult {
        await BoundedDNSResolver.resolve(host: endpoint.host, timeout: timeout,
            lookup: { host in Self.lookup(host) })
    }

    private static func lookup(_ host: String) -> EndpointDNSProbeResult {
        let startedAt = DispatchTime.now().uptimeNanoseconds
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_STREAM
        hints.ai_protocol = IPPROTO_TCP
        var list: UnsafeMutablePointer<addrinfo>?
        let status = host.withCString { getaddrinfo($0, nil, &hints, &list) }
        defer { if let list { freeaddrinfo(list) } }
        guard status == 0 else {
            let message = String(cString: gai_strerror(status))
            return .failed(message)
        }

        var addresses: [String] = []
        var current = list
        while let item = current {
            let info = item.pointee
            if let socketAddress = info.ai_addr {
                var numericHost = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                let result = getnameinfo(socketAddress, info.ai_addrlen,
                    &numericHost, socklen_t(numericHost.count), nil, 0, NI_NUMERICHOST)
                if result == 0 {
                    let address = String(cString: numericHost)
                    if !addresses.contains(address) { addresses.append(address) }
                }
            }
            current = info.ai_next
        }
        guard !addresses.isEmpty else { return .failed("No addresses were returned") }
        let elapsed = DispatchTime.now().uptimeNanoseconds - startedAt
        return .resolved(addresses: addresses,
            milliseconds: Int(elapsed / 1_000_000))
    }
}

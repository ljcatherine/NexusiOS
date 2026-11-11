import Foundation
import Observation

struct DiscoveredSSHService: Identifiable, Equatable {
    var id: String { "\(name).\(host).\(port)" }
    let name: String
    let host: String
    let port: Int
}

@MainActor @Observable
final class SSHServiceDiscovery: NSObject, NetServiceBrowserDelegate, NetServiceDelegate {
    private(set) var services: [DiscoveredSSHService] = []
    private(set) var isSearching = false
    var error: String?

    @ObservationIgnored private var browser: NetServiceBrowser?
    @ObservationIgnored private var resolving: [String: NetService] = [:]
    @ObservationIgnored private var serviceResultsByKey: [String: DiscoveredSSHService] = [:]
    @ObservationIgnored private var stopTask: Task<Void, Never>?

    func start() {
        stop()
        services = []
        serviceResultsByKey = [:]
        error = nil
        let browser = NetServiceBrowser()
        self.browser = browser
        browser.delegate = self
        isSearching = true
        browser.searchForServices(ofType: "_ssh._tcp.", inDomain: "local.")
        stopTask = Task {
            try? await Task.sleep(for: .seconds(15))
            guard !Task.isCancelled else { return }
            self.stop()
            if self.services.isEmpty {
                self.error = "No Bonjour SSH services were found on this local network."
            }
        }
    }

    func stop() {
        stopTask?.cancel()
        stopTask = nil
        browser?.stop()
        browser?.delegate = nil
        browser = nil
        resolving.values.forEach { $0.stop() }
        resolving.removeAll()
        isSearching = false
    }

    func netServiceBrowser(_ browser: NetServiceBrowser, didFind service: NetService, moreComing: Bool) {
        guard browser === self.browser, isSearching else { return }
        let key = serviceKey(service)
        resolving[key]?.stop()
        resolving[key] = service
        service.delegate = self
        service.resolve(withTimeout: 5)
    }

    func netServiceBrowser(_ browser: NetServiceBrowser, didRemove service: NetService, moreComing: Bool) {
        guard browser === self.browser else { return }
        let key = serviceKey(service)
        resolving[key]?.stop()
        resolving[key] = nil
        if let removed = serviceResultsByKey.removeValue(forKey: key) {
            let stillAdvertised = serviceResultsByKey.values.contains { $0.id == removed.id }
            if !stillAdvertised { services.removeAll { $0.id == removed.id } }
        }
    }

    func netServiceBrowser(_ browser: NetServiceBrowser, didNotSearch errorDict: [String: NSNumber]) {
        guard browser === self.browser else { return }
        error = "Bonjour SSH discovery could not start. Check Nexus local-network permission in iOS Settings."
        stop()
    }

    func netServiceDidResolveAddress(_ sender: NetService) {
        let key = serviceKey(sender)
        guard isSearching, resolving[key] === sender else { return }
        guard let host = sender.hostName?.trimmingCharacters(in: .whitespacesAndNewlines),
              !host.isEmpty, (1...65535).contains(sender.port) else {
            error = "A discovered SSH service did not provide a usable host and port."
            resolving[key] = nil
            return
        }
        let result = DiscoveredSSHService(name: sender.name, host: host, port: sender.port)
        if let previous = serviceResultsByKey.updateValue(result, forKey: key) {
            services.removeAll { $0.id == previous.id }
        }
        if !services.contains(where: { $0.id == result.id }) { services.append(result) }
        services.sort { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
        resolving[key] = nil
    }

    func netService(_ sender: NetService, didNotResolve errorDict: [String: NSNumber]) {
        guard resolving[serviceKey(sender)] === sender else { return }
        resolving[serviceKey(sender)] = nil
    }

    private func serviceKey(_ service: NetService) -> String {
        "\(service.name)|\(service.type)|\(service.domain)"
    }
}

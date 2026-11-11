import XCTest
@testable import NexusCore

final class ConfigurationTests: XCTestCase {
    func testEmptyDeploymentConfigurationPreconfiguresNothing() {
        let empty = DeploymentConfiguration(infoDictionary: [:])
        XCTAssertNil(empty.gatewayHost)
        XCTAssertNil(empty.gatewayOrigin)
        XCTAssertFalse(empty.hasManagedAccessGateway)
        XCTAssertNil(empty.defaultAIEndpoint)
        XCTAssertTrue(empty.suggestedDevices.isEmpty)
        XCTAssertNil(empty.relayTarget(forUsername: "user"))
        let blank = DeploymentConfiguration(infoDictionary: [DeploymentConfiguration.Key.gatewayHost: "  ",
            DeploymentConfiguration.Key.relayDevices: [["name": "Server", "username": "user", "target": "server"]]])
        XCTAssertNil(blank.gatewayHost)
        XCTAssertTrue(blank.suggestedDevices.isEmpty, "relay devices need a gateway host")
    }

    func testDeploymentConfigurationBuildsRelaySuggestions() {
        let config = DeploymentConfiguration(infoDictionary: [
            DeploymentConfiguration.Key.gatewayHost: " Nexus.Example.workers.dev ",
            DeploymentConfiguration.Key.accessIssuer: "https://team.cloudflareaccess.com",
            DeploymentConfiguration.Key.accessClientID: "00000000-0000-0000-0000-000000000000",
            DeploymentConfiguration.Key.defaultAIEndpoint: "http://192.0.2.20:8081/v1",
            DeploymentConfiguration.Key.relayDevices: [
                ["name": "Workstation", "username": "user", "target": "nixos"],
                ["name": "Home Server", "username": "server", "target": "debian"],
                ["name": "Incomplete", "username": "", "target": "other"],
                ["name": 7]
            ]
        ])
        XCTAssertEqual(config.gatewayHost, "nexus.example.workers.dev")
        XCTAssertEqual(config.gatewayOrigin, "https://nexus.example.workers.dev")
        XCTAssertTrue(config.hasManagedAccessGateway)
        XCTAssertEqual(config.relayTarget(forUsername: "SERVER"), "debian")
        XCTAssertNil(config.relayTarget(forUsername: "someone-else"))
        let devices = config.suggestedDevices
        XCTAssertEqual(devices.map(\.name), ["Workstation", "Home Server"])
        XCTAssertEqual(devices.map(\.username), ["user", "server"])
        XCTAssertEqual(devices.flatMap(\.endpoints).map(\.host), ["nexus.example.workers.dev", "nexus.example.workers.dev"])
        XCTAssertEqual(devices.flatMap(\.endpoints).map(\.port), [443, 443])
        XCTAssertEqual(devices.flatMap(\.endpoints).map(\.kind), [.cloudflare, .cloudflare])
        XCTAssertEqual(devices.flatMap(\.endpoints).map(\.relayTarget), ["nixos", "debian"])
        XCTAssertTrue(Endpoint(host: "example.invalid").isExampleAddress)
        XCTAssertFalse(Endpoint(host: "myexample.invalid").isExampleAddress)
    }

    func testConfigurationRoundTripContainsNoCredentials() throws {
        let device = Device(name: "Server", username: "user", endpoints: [.init(host: "server.tailnet.ts.net", kind: .tailscale)])
        let encoded = try JSONEncoder().encode(Configuration(devices: [device]))
        let decoded = try Configuration.decode(encoded)
        XCTAssertEqual(decoded.devices, [device])
        let json = String(decoding: encoded, as: UTF8.self)
        XCTAssertFalse(json.contains("secret")); XCTAssertFalse(json.contains("passphrase"))
    }
    func testRejectsBadConfigurationAndDuplicateIdentities() throws {
        var device = Device(name: "Server", username: "user", endpoints: [.init(host: "127.0.0.1")])
        device.endpoints[0].port = 0
        XCTAssertThrowsError(try device.validate())
        device.endpoints[0].port = 22; device.endpoints[0].host = "host; touch /tmp/pwned"
        XCTAssertThrowsError(try device.validate())
        device.endpoints[0].host = "100.100.1.2"
        XCTAssertThrowsError(try Configuration.decode(JSONEncoder().encode(Configuration(devices: [device, device]))))
        device.endpoints.append(device.endpoints[0])
        XCTAssertThrowsError(try device.validate())
    }
    func testEndpointPriorityIsStable() {
        let device = Device(name: "Server", username: "user", endpoints: [
            .init(host: "tail", kind: .tailscale, priority: 2),
            .init(host: "lan", priority: 0), .init(host: "second-lan", priority: 0)])
        XCTAssertEqual(device.orderedEndpoints.map(\.host), ["lan", "second-lan", "tail"])
    }
    func testHostTrustNeverAcceptsUnknownOrChangedKey() {
        XCTAssertEqual(HostTrust.evaluate(stored: nil, presented: "new"), .confirmationRequired)
        XCTAssertEqual(HostTrust.evaluate(stored: "old", presented: "new"), .changed)
        XCTAssertEqual(HostTrust.evaluate(stored: "same", presented: "same"), .trusted)
    }
    func testShellQuotingProtectsMetacharacters() {
        XCTAssertEqual(Shell.quote("a'b;$(id)"), "'a'\"'\"'b;$(id)'")
        let id = UUID()
        XCTAssertEqual(Shell.tmux(sessionID: id), "tmux new-session -A -s 'nexus-\(id.uuidString.lowercased())'\r")
    }
}

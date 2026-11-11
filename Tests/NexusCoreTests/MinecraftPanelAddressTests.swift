import XCTest
@testable import NexusCore

final class MinecraftPanelAddressTests: XCTestCase {
    func testAcceptsPrivateHTTPSAddressAndCanonicalizesOriginComparison() throws {
        let panel = try MinecraftPanelAddress("  HTTPS://Panel.Tailnet.Example:8443/control  ")

        XCTAssertEqual(panel.url.host, "Panel.Tailnet.Example")
        XCTAssertTrue(panel.origin.allows(URL(string: "https://panel.tailnet.example:8443/login")!))
        XCTAssertTrue(panel.origin.allows(URL(string: "https://PANEL.TAILNET.EXAMPLE:8443/instances")!))
    }

    func testRejectsInsecureOrCredentialBearingPanelAddresses() {
        let invalid = [
            "http://panel.example.com",
            "https://user:password@panel.example.com",
            "https://panel.example.com?token=secret",
            "https://panel.example.com#section",
            "https://example.invalid",
            "https://ps5.example.invalid",
            "https://panel.example.com:0",
            "https://panel.example.com:65536",
            "not a URL"
        ]

        for value in invalid {
            XCTAssertThrowsError(try MinecraftPanelAddress(value), "Accepted: \(value)")
        }
    }

    func testOriginBlocksSchemeHostPortAndUserInfoChanges() throws {
        let origin = try MinecraftPanelAddress("https://panel.example.com:8443").origin
        let blocked = [
            "http://panel.example.com:8443/login",
            "https://panel.example.com/login",
            "https://other.example.com:8443/login",
            "https://user@panel.example.com:8443/login"
        ]

        for value in blocked {
            XCTAssertFalse(origin.allows(URL(string: value)!), "Allowed: \(value)")
        }
    }

    func testChangingSavedPanelAddressReplacesTheAllowedOrigin() throws {
        let previous = try MinecraftPanelAddress("https://old-panel.example.com").origin
        let replacement = try MinecraftPanelAddress("https://new-panel.example.com").origin

        XCTAssertFalse(replacement.allows(URL(string: "https://old-panel.example.com/login")!))
        XCTAssertTrue(replacement.allows(URL(string: "https://new-panel.example.com/login")!))
        XCTAssertTrue(previous.allows(URL(string: "https://old-panel.example.com/login")!))
    }
}

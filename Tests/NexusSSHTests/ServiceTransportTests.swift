import XCTest
@testable import NexusSSH

final class ServiceTransportTests: XCTestCase {
    func testSystemdUnitValidationAcceptsServiceNamesOnly() {
        XCTAssertTrue(ServiceTransport.isValidUnit("ssh.service"))
        XCTAssertTrue(ServiceTransport.isValidUnit("minecraft-server@vanilla.service"))
        XCTAssertTrue(ServiceTransport.isValidUnit("user_1.service"))

        for invalid in ["ssh", "ssh.socket", "../ssh.service", "ssh.service;id",
                        "ssh service.service", "-ssh.service", "ssh.service\nwhoami"] {
            XCTAssertFalse(ServiceTransport.isValidUnit(invalid), "Accepted: \(invalid)")
        }
    }

    func testServiceListParserKeepsDescriptionsAndDropsMalformedUnits() {
        let output = """
          ssh.service loaded active running OpenBSD Secure Shell server
          minecraft@vanilla.service loaded inactive dead Vanilla Minecraft server
          bad.service;id loaded active running rejected name
          malformed.service loaded
          dbus.service loaded active running
        """
        let services = ServiceTransport.parseServices(output)
        XCTAssertEqual(services.map(\.name), ["dbus.service", "minecraft@vanilla.service", "ssh.service"])
        let byName = Dictionary(uniqueKeysWithValues: services.map { ($0.name, $0) })
        XCTAssertEqual(byName["minecraft@vanilla.service"]?.description, "Vanilla Minecraft server")
        XCTAssertFalse(byName["minecraft@vanilla.service"]?.isActive ?? true)
        XCTAssertEqual(byName["ssh.service"]?.description, "OpenBSD Secure Shell server")
        XCTAssertTrue(byName["ssh.service"]?.isActive ?? false)
        XCTAssertEqual(byName["dbus.service"]?.description, "")
    }

    func testProcessParserPreservesCommandSpacingAndDropsInvalidMeasurements() {
        let output = """
            42 user 12.5 3.25 S minecraft server
            43 root 0.0 1.0 I systemd
            0 root 0.0 1.0 S invalid-pid
            44 root nan 1.0 S invalid-cpu
            45 root 1.0 inf S invalid-memory
            46 root -1.0 1.0 S negative-cpu
        """
        let processes = ServiceTransport.parseProcesses(output)
        XCTAssertEqual(processes.map(\.pid), [42, 43])
        XCTAssertEqual(processes[0].command, "minecraft server")
        XCTAssertEqual(processes[0].cpuPercent, 12.5)
        XCTAssertEqual(processes[0].memoryPercent, 3.25)
    }

    func testNixOSValidationCommandIsNonInteractiveDryBuild() throws {
        XCTAssertEqual(try ServiceTransport.nixosCommand(.validate, flakeAttribute: nil),
                       "sudo -n nixos-rebuild dry-build")
        XCTAssertEqual(try ServiceTransport.nixosCommand(.validate, flakeAttribute: "nixosConfigurations.desktop"),
                       "sudo -n nixos-rebuild dry-build --flake '/etc/nixos#nixosConfigurations.desktop'")
    }

    func testNixOSSwitchRequiresSuccessfulDryBuildFirst() throws {
        XCTAssertEqual(try ServiceTransport.nixosCommand(.switchSystem, flakeAttribute: "host_1"),
                       "sudo -n nixos-rebuild dry-build --flake '/etc/nixos#host_1' && sudo -n nixos-rebuild switch --flake '/etc/nixos#host_1'")
    }

    func testNixOSFlakeAttributeRejectsShellSyntaxAndOversizedValues() {
        for invalid in ["; touch /tmp/pwned", "host$(id)", "host name", "host#other", ""] {
            XCTAssertThrowsError(try ServiceTransport.nixosCommand(.validate, flakeAttribute: invalid))
        }
        XCTAssertThrowsError(try ServiceTransport.nixosCommand(.validate, flakeAttribute: String(repeating: "a", count: 129)))
    }
}

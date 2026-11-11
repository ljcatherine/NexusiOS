import XCTest
import Citadel
import NIO
import NIOSSH
import NexusCore
@testable import NexusSSH

private struct PinnedFingerprintDelegate: NIOSSHClientServerAuthenticationDelegate, Sendable {
    let expectedFingerprint: String

    func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
        let publicKey = String(openSSHPublicKey: hostKey)
        do {
            guard try HostKeyVerifier.fingerprint(publicKey) == expectedFingerprint else {
                validationCompletePromise.fail(SSHFailure.invalidHostKey)
                return
            }
            validationCompletePromise.succeed(())
        } catch {
            validationCompletePromise.fail(SSHFailure.invalidHostKey)
        }
    }
}

final class LiveSSHDiagnosticTests: XCTestCase {
    /// Opt-in read-only handshake probe. Uses an ephemeral key and a caller-supplied,
    /// independently verified host fingerprint; it never runs a remote command.
    func testLiveNiosshHandshakeReachesAuthenticationWhenConfigured() async throws {
        let environment = ProcessInfo.processInfo.environment
        guard let host = environment["NEXUS_LIVE_SSH_HOST"],
              let username = environment["NEXUS_LIVE_SSH_USERNAME"],
              let expectedFingerprint = environment["NEXUS_LIVE_SSH_HOST_FINGERPRINT"] else {
            throw XCTSkip("Set NEXUS_LIVE_SSH_HOST, NEXUS_LIVE_SSH_USERNAME, and NEXUS_LIVE_SSH_HOST_FINGERPRINT to run the pinned live probe.")
        }
        let port = Int(environment["NEXUS_LIVE_SSH_PORT"] ?? "22") ?? 22
        let endpoint = Endpoint(host: host, port: port)
        let keyPair = try SSHKeyGenerator.generate(comment: "nexus-live-diagnostic")
        let device = Device(name: "Live SSH diagnostic", username: username, endpoints: [endpoint])
        let authentication = try SSHTransport.authentication(
            device: device,
            credential: Credential(secret: keyPair.privateKey)
        )
        var settings = SSHClientSettings(
            host: host,
            port: port,
            authenticationMethod: { authentication },
            hostKeyValidator: .custom(PinnedFingerprintDelegate(expectedFingerprint: expectedFingerprint))
        )
        settings.connectTimeout = .seconds(10)

        do {
            let client = try await SSHClientConnector.connect(to: settings)
            try await client.close()
            XCTFail("An ephemeral diagnostic key unexpectedly authenticated.")
        } catch let error as SSHClientError {
            guard case .allAuthenticationOptionsFailed = error else {
                XCTFail("SSH reached an unexpected authentication outcome: \(SSHDiagnosticFormatter.describe(error))")
                return
            }
            // Successful SSH key exchange and trusted host-key validation; only the
            // deliberately uninstalled ephemeral user key was rejected.
        } catch {
            XCTFail("SSH failed before the expected authentication rejection: \(SSHDiagnosticFormatter.describe(error))")
        }
    }

    /// Opt-in read-only app metrics probe against a pinned Linux host. The app's
    /// command/parser output is checked against independent procfs/df readings.
    func testLiveHostMetricsMatchIndependentLinuxReadingsWhenConfigured() async throws {
        let environment = ProcessInfo.processInfo.environment
        guard let host = environment["NEXUS_LIVE_SSH_HOST"],
              let username = environment["NEXUS_LIVE_SSH_USERNAME"],
              let expectedFingerprint = environment["NEXUS_LIVE_SSH_HOST_FINGERPRINT"],
              let hostPublicKey = environment["NEXUS_LIVE_SSH_HOST_PUBLIC_KEY"],
              let keyPath = environment["NEXUS_LIVE_SSH_PRIVATE_KEY_PATH"] else {
            throw XCTSkip("Set the pinned live SSH host, username, host public key/fingerprint, and private-key file path to run this read-only metrics comparison.")
        }
        XCTAssertEqual(try HostKeyVerifier.fingerprint(hostPublicKey), expectedFingerprint,
                       "The provided host public key must match the independently verified fingerprint.")
        let port = Int(environment["NEXUS_LIVE_SSH_PORT"] ?? "22") ?? 22
        let endpoint = Endpoint(host: host, port: port)
        let device = Device(name: "Live read-only metrics check", username: username, endpoints: [endpoint])
        let secrets = MemorySecrets()
        let credential = Credential(secret: try String(contentsOfFile: keyPath, encoding: .utf8),
            passphrase: environment["NEXUS_LIVE_SSH_KEY_PASSPHRASE"] ?? "")
        try secrets.write(JSONEncoder().encode(credential), account: SSHTransport.credentialAccount(device))
        try secrets.write(Data(hostPublicKey.utf8), account: HostKeyVerifier.account(endpoint))

        let metrics = try await SSHTransport().fetchMetrics(device: device, endpoint: endpoint,
                                                             secrets: secrets, timeout: 20)
        let services = try await ServiceTransport().listServices(device: device, endpoint: endpoint,
                                                                  secrets: secrets, timeout: 20)
        XCTAssertFalse(services.isEmpty, "The live systemd listing should contain service units.")
        XCTAssertTrue(services.contains { $0.name == "ssh.service" && $0.isActive },
                      "The SSH service should be present and active on the Debian test host.")
        let inspection = try await ServiceTransport().inspectSystem(device: device, endpoint: endpoint,
                                                                     secrets: secrets, timeout: 20)
        XCTAssertTrue(inspection.distribution.localizedCaseInsensitiveContains("Debian"))
        XCTAssertFalse(inspection.kernel.isEmpty)
        XCTAssertFalse(inspection.isNixOS)
        let processes = try await ServiceTransport().topProcesses(device: device, endpoint: endpoint,
                                                                   secrets: secrets, timeout: 20)
        XCTAssertFalse(processes.isEmpty)
        XCTAssertTrue(processes.allSatisfy { $0.pid > 0 && !$0.command.isEmpty })
        let sftp = SFTPTransport()
        try await sftp.connect(device: device, endpoint: endpoint, secrets: secrets, timeout: 20)
        let homeEntries = try await sftp.listDirectory(at: ".")
        XCTAssertTrue(homeEntries.allSatisfy { $0.path.hasPrefix("/") && !$0.name.isEmpty })
        await sftp.disconnect()
        XCTAssertGreaterThan(metrics.uptimeSeconds ?? 0, 0)
        XCTAssertGreaterThan(metrics.logicalCPUCount ?? 0, 0)
        XCTAssertNotNil(metrics.memoryTotalBytes)
        XCTAssertNotNil(metrics.memoryAvailableBytes)
        XCTAssertNotNil(metrics.rootFilesystem)
        XCTAssertFalse(metrics.networkInterfaces.isEmpty)
        XCTAssertTrue(metrics.networkInterfaces.allSatisfy { $0.interface != "lo" })

        let authentication = try SSHTransport.authentication(device: device, credential: credential)
        var settings = SSHClientSettings(host: host, port: port,
            authenticationMethod: { authentication },
            hostKeyValidator: .custom(PinnedFingerprintDelegate(expectedFingerprint: expectedFingerprint)))
        settings.connectTimeout = .seconds(10)
        let client = try await SSHClientConnector.connect(to: settings)
        let independent = try await client.executeCommand(#"""
            printf 'uptime\t'; awk '{printf "%.2f\n", $1}' /proc/uptime
            awk '$1 ~ /^cpu[0-9]+$/ { count++ } END { printf "cpu_count\t%d\n", count }' /proc/stat
            awk '/^MemTotal:/ { total=$2 } /^MemAvailable:/ { available=$2 } END { printf "memory\t%.0f\t%.0f\n", total*1024, available*1024 }' /proc/meminfo
            df -Pk / | awk 'NR == 2 { printf "filesystem\t%.0f\t%.0f\t%.0f\n", $2*1024, $3*1024, $4*1024 }'
            """#, maxResponseSize: 8 * 1024)
        try await client.close()
        let lines = String(decoding: independent.readableBytesView, as: UTF8.self)
            .split(whereSeparator: \.isNewline).map { $0.split(separator: "\t", omittingEmptySubsequences: false) }
        func values(_ name: String) -> [Substring]? {
            lines.first(where: { $0.first == Substring(name) })
        }
        let cpuCountFields = try XCTUnwrap(values("cpu_count"))
        let expectedCPUCount = try XCTUnwrap(Int(try XCTUnwrap(cpuCountFields.dropFirst().first)))
        XCTAssertEqual(metrics.logicalCPUCount, expectedCPUCount)
        let memory = try XCTUnwrap(values("memory"))
        XCTAssertEqual(metrics.memoryTotalBytes, try XCTUnwrap(UInt64(try XCTUnwrap(memory.dropFirst().first))))
        XCTAssertNotNil(UInt64(try XCTUnwrap(memory.dropFirst(2).first)))
        let filesystem = try XCTUnwrap(values("filesystem"))
        XCTAssertEqual(metrics.rootFilesystem?.totalBytes,
                       try XCTUnwrap(UInt64(try XCTUnwrap(filesystem.dropFirst().first))))
        let uptimeFields = try XCTUnwrap(values("uptime"))
        let independentUptime = try XCTUnwrap(Double(try XCTUnwrap(uptimeFields.dropFirst().first)))
        XCTAssertLessThan(abs((metrics.uptimeSeconds ?? 0) - independentUptime), 10)
    }

    /// Read-only NixOS metrics check. The host fingerprint is taken from a trusted
    /// known-host record and the production parser is compared with independent procfs/df output.
    func testLiveNixOSMetricsMatchIndependentLinuxReadingsWhenConfigured() async throws {
        let environment = ProcessInfo.processInfo.environment
        guard let host = environment["NEXUS_LIVE_NIXOS_HOST"],
              let username = environment["NEXUS_LIVE_NIXOS_USERNAME"],
              let expectedFingerprint = environment["NEXUS_LIVE_NIXOS_HOST_FINGERPRINT"],
              let hostPublicKey = environment["NEXUS_LIVE_NIXOS_HOST_PUBLIC_KEY"],
              let keyPath = environment["NEXUS_LIVE_NIXOS_PRIVATE_KEY_PATH"] else {
            throw XCTSkip("Set the pinned NixOS host, username, trusted host key, and private-key path to run this read-only comparison.")
        }
        XCTAssertEqual(try HostKeyVerifier.fingerprint(hostPublicKey), expectedFingerprint)
        let port = Int(environment["NEXUS_LIVE_NIXOS_PORT"] ?? "22") ?? 22
        let endpoint = Endpoint(host: host, port: port)
        let device = Device(name: "Live NixOS metrics check", username: username, endpoints: [endpoint])
        let credential = Credential(secret: try String(contentsOfFile: keyPath, encoding: .utf8),
            passphrase: environment["NEXUS_LIVE_NIXOS_KEY_PASSPHRASE"] ?? "")
        let secrets = MemorySecrets()
        try secrets.write(JSONEncoder().encode(credential), account: SSHTransport.credentialAccount(device))
        try secrets.write(Data(hostPublicKey.utf8), account: HostKeyVerifier.account(endpoint))

        let metrics = try await SSHTransport().fetchMetrics(device: device, endpoint: endpoint,
                                                             secrets: secrets, timeout: 20)
        let inspection = try await ServiceTransport().inspectSystem(device: device, endpoint: endpoint,
                                                                     secrets: secrets, timeout: 20)
        XCTAssertTrue(inspection.isNixOS)
        XCTAssertTrue(inspection.distribution.localizedCaseInsensitiveContains("NixOS"))
        XCTAssertGreaterThan(metrics.uptimeSeconds ?? 0, 0)
        XCTAssertGreaterThan(metrics.logicalCPUCount ?? 0, 0)
        XCTAssertNotNil(metrics.memoryTotalBytes)
        XCTAssertNotNil(metrics.memoryAvailableBytes)
        XCTAssertNotNil(metrics.rootFilesystem)
        XCTAssertTrue(metrics.networkInterfaces.contains { $0.interface != "lo" })

        let authentication = try SSHTransport.authentication(device: device, credential: credential)
        var settings = SSHClientSettings(host: host, port: port,
            authenticationMethod: { authentication },
            hostKeyValidator: .custom(PinnedFingerprintDelegate(expectedFingerprint: expectedFingerprint)))
        settings.connectTimeout = .seconds(10)
        let client = try await SSHClientConnector.connect(to: settings)
        let independent = try await client.executeCommand(#"""
            printf 'uptime\t'; awk '{printf "%.2f\n", $1}' /proc/uptime
            awk '$1 ~ /^cpu[0-9]+$/ { count++ } END { printf "cpu_count\t%d\n", count }' /proc/stat
            awk '/^MemTotal:/ { total=$2 } /^MemAvailable:/ { available=$2 } END { printf "memory\t%.0f\t%.0f\n", total*1024, available*1024 }' /proc/meminfo
            df -Pk / | awk 'NR == 2 { printf "filesystem\t%.0f\t%.0f\t%.0f\n", $2*1024, $3*1024, $4*1024 }'
            """#, maxResponseSize: 8 * 1024)
        try await client.close()
        let lines = String(decoding: independent.readableBytesView, as: UTF8.self)
            .split(whereSeparator: \.isNewline)
            .map { $0.split(separator: "\t", omittingEmptySubsequences: false) }
        func values(_ name: String) -> [Substring]? {
            lines.first(where: { $0.first == Substring(name) })
        }
        let cpuCount = try XCTUnwrap(values("cpu_count"))
        XCTAssertEqual(metrics.logicalCPUCount,
                       try XCTUnwrap(Int(try XCTUnwrap(cpuCount.dropFirst().first))))
        let memory = try XCTUnwrap(values("memory"))
        XCTAssertEqual(metrics.memoryTotalBytes,
                       try XCTUnwrap(UInt64(try XCTUnwrap(memory.dropFirst().first))))
        let filesystem = try XCTUnwrap(values("filesystem"))
        XCTAssertEqual(metrics.rootFilesystem?.totalBytes,
                       try XCTUnwrap(UInt64(try XCTUnwrap(filesystem.dropFirst().first))))
        let uptime = try XCTUnwrap(values("uptime"))
        let independentUptime = try XCTUnwrap(Double(try XCTUnwrap(uptime.dropFirst().first)))
        XCTAssertLessThan(abs((metrics.uptimeSeconds ?? 0) - independentUptime), 10)
    }
}

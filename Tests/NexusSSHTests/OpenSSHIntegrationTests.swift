import XCTest
import Citadel
import NexusCore
@testable import NexusSSH

private actor OutputBuffer {
    var data = Data()
    func append(_ bytes: Data) { data.append(bytes) }
    func text() -> String { String(decoding: data, as: UTF8.self) }
}

private struct SlowConnectionBackend: SSHConnectionBackend {
    func connect(settings: SSHClientSettings) async throws -> SSHClient {
        try await Task.sleep(for: .seconds(60))
        throw CancellationError()
    }
}

private actor DeferredConnectionBackend: SSHConnectionBackend {
    private var pending: CheckedContinuation<SSHClient, Error>?
    private var startWaiters: [CheckedContinuation<Void, Never>] = []

    func connect(settings: SSHClientSettings) async throws -> SSHClient {
        try await withCheckedThrowingContinuation { continuation in
            pending = continuation
            startWaiters.forEach { $0.resume() }
            startWaiters.removeAll()
        }
    }

    func waitUntilStarted() async {
        if pending != nil { return }
        await withCheckedContinuation { startWaiters.append($0) }
    }

    func failPendingHandshake() {
        let continuation = pending
        pending = nil
        continuation?.resume(throwing: SSHFailure.connectionFailed)
    }
}

private struct UnexpectedConnectionBackend: SSHConnectionBackend {
    func connect(settings: SSHClientSettings) async throws -> SSHClient {
        throw SSHFailure.connectionFailed
    }
}

final class OpenSSHIntegrationTests: XCTestCase {
    func testGeneratedEd25519KeyAuthenticatesToDisposableOpenSSH() async throws {
        let environment = ProcessInfo.processInfo.environment
        guard let username = environment["NEXUS_TEST_USER"],
              let fixturePath = environment["FIXTURE_DIR"] else {
            throw XCTSkip("Run bash scripts/test-openssh.sh to start the disposable loopback SSH fixture.")
        }

        let authorizedKeys = URL(fileURLWithPath: fixturePath).appendingPathComponent("client.pub")
        let originalAuthorizedKeys = try String(contentsOf: authorizedKeys, encoding: .utf8)
        let pair = try SSHKeyGenerator.generate(comment: "nexus-fixture")
        try (originalAuthorizedKeys + pair.publicKey + "\n").write(to: authorizedKeys, atomically: true, encoding: .utf8)
        defer { try? originalAuthorizedKeys.write(to: authorizedKeys, atomically: true, encoding: .utf8) }

        let endpoint = Endpoint(host: "127.0.0.1", port: 22222)
        let device = Device(name: "Generated-key fixture", username: username, endpoints: [endpoint])
        let secrets = MemorySecrets()
        try secrets.write(JSONEncoder().encode(Credential(secret: pair.privateKey)),
            account: SSHTransport.credentialAccount(device))
        let transport = SSHTransport()

        do {
            do {
                try await transport.run(device: device, endpoint: endpoint, secrets: secrets, timeout: 5,
                    onConnected: {}, onOutput: { _ in })
                XCTFail("Generated-key connection passed without approving first-use host trust")
            } catch let challenge as HostKeyChallenge {
                XCTAssertEqual(challenge.fingerprint, environment["NEXUS_TEST_HOST_FINGERPRINT"])
                try HostKeyVerifier.approve(challenge, secrets: secrets)
            }

            let output = try await runFixtureCommand("NEXUS_GENERATED_KEY_OK", device: device,
                transport: transport, endpoint: endpoint, secrets: secrets, timeout: 5)
            XCTAssertTrue(output.contains("NEXUS_GENERATED_KEY_OK"), output)
        } catch {
            await transport.disconnect()
            throw error
        }
        await transport.disconnect()
    }

    func testServerRejectedKeyReturnsSpecificFailureAfterHostTrust() async throws {
        let environment = ProcessInfo.processInfo.environment
        guard let keyPath = environment["NEXUS_TEST_REJECTED_PRIVATE_KEY"],
              let username = environment["NEXUS_TEST_USER"] else {
            throw XCTSkip("Run bash scripts/test-openssh.sh to prepare a second disposable Ed25519 key.")
        }
        let endpoint = Endpoint(host: "127.0.0.1", port: 22222)
        let device = Device(name: "Rejected key fixture", username: username, endpoints: [endpoint])
        let secrets = MemorySecrets()
        let credential = Credential(secret: try String(contentsOfFile: keyPath, encoding: .utf8))
        try secrets.write(JSONEncoder().encode(credential), account: SSHTransport.credentialAccount(device))
        let pipeline = SSHConnectionPipeline()

        do {
            _ = try await pipeline.connect(device: device, endpoint: endpoint, secrets: secrets, timeout: 5)
            XCTFail("The untrusted fixture host unexpectedly passed first-use verification")
        } catch let challenge as HostKeyChallenge {
            try HostKeyVerifier.approve(challenge, secrets: secrets)
        }

        do {
            _ = try await pipeline.connect(device: device, endpoint: endpoint, secrets: secrets, timeout: 5)
            XCTFail("The server unexpectedly accepted a public key absent from authorized_keys")
        } catch let failure as SSHHandshakeFailure {
            XCTAssertEqual(failure.failure, .authenticationRejected)
            XCTAssertFalse(failure.diagnostic.isEmpty)
            XCTAssertFalse(failure.diagnostic.contains("fixture-private-host"))
        }
    }

    func testHandshakeTimeoutAndCancellationReturnWithoutWaitingForBackend() async throws {
        let environment = ProcessInfo.processInfo.environment
        guard let keyPath = environment["NEXUS_TEST_PRIVATE_KEY"],
              let username = environment["NEXUS_TEST_USER"] else {
            throw XCTSkip("Run bash scripts/test-openssh.sh to prepare an ephemeral Ed25519 key.")
        }
        let endpoint = Endpoint(host: "127.0.0.1", port: 22222)
        let device = Device(name: "Slow backend fixture", username: username, endpoints: [endpoint])
        let secrets = MemorySecrets()
        let credential = Credential(secret: try String(contentsOfFile: keyPath, encoding: .utf8),
            passphrase: environment["NEXUS_TEST_KEY_PASSPHRASE"] ?? "")
        try secrets.write(JSONEncoder().encode(credential), account: SSHTransport.credentialAccount(device))
        let pipeline = SSHConnectionPipeline(backend: SlowConnectionBackend())

        do {
            _ = try await pipeline.connect(device: device, endpoint: endpoint, secrets: secrets, timeout: 3)
            XCTFail("A slow backend exceeded the handshake deadline without failing")
        } catch SSHFailure.connectionTimedOut {}

        let canceled = Task {
            try await pipeline.connect(device: device, endpoint: endpoint, secrets: secrets, timeout: 120)
        }
        try await Task.sleep(for: .milliseconds(100))
        canceled.cancel()
        do {
            _ = try await canceled.value
            XCTFail("A canceled handshake unexpectedly connected")
        } catch is CancellationError {}
    }

    func testCanceledHandshakeReturnsEvenWhenBackendIgnoresCancellation() async throws {
        let environment = ProcessInfo.processInfo.environment
        guard let keyPath = environment["NEXUS_TEST_PRIVATE_KEY"],
              let username = environment["NEXUS_TEST_USER"] else {
            throw XCTSkip("Run bash scripts/test-openssh.sh to prepare an ephemeral Ed25519 key.")
        }
        let endpoint = Endpoint(host: "127.0.0.1", port: 22222)
        let device = Device(name: "Non-cooperative backend fixture", username: username, endpoints: [endpoint])
        let secrets = MemorySecrets()
        let credential = Credential(secret: try String(contentsOfFile: keyPath, encoding: .utf8),
            passphrase: environment["NEXUS_TEST_KEY_PASSPHRASE"] ?? "")
        try secrets.write(JSONEncoder().encode(credential), account: SSHTransport.credentialAccount(device))
        let backend = DeferredConnectionBackend()
        let pipeline = SSHConnectionPipeline(backend: backend)
        let connection = Task {
            try await pipeline.connect(device: device, endpoint: endpoint, secrets: secrets, timeout: 120)
        }

        await backend.waitUntilStarted()
        connection.cancel()
        do {
            _ = try await connection.value
            XCTFail("A canceled handshake unexpectedly connected")
        } catch is CancellationError {}

        // Complete the simulated third-party operation only after the caller has returned.
        // This verifies that a late backend failure cannot resume the continuation twice.
        await backend.failPendingHandshake()
    }

    func testWrongEncryptedKeyPassphraseFailsBeforeNetwork() async throws {
        let environment = ProcessInfo.processInfo.environment
        guard let keyPath = environment["NEXUS_TEST_PRIVATE_KEY"],
              let username = environment["NEXUS_TEST_USER"],
              environment["NEXUS_TEST_KEY_PASSPHRASE"] != nil else {
            throw XCTSkip("This regression runs during the encrypted-key OpenSSH fixture pass.")
        }
        let endpoint = Endpoint(host: "127.0.0.1", port: 22222)
        let device = Device(name: "Wrong passphrase fixture", username: username, endpoints: [endpoint])
        let secrets = MemorySecrets()
        let credential = Credential(secret: try String(contentsOfFile: keyPath, encoding: .utf8),
            passphrase: "intentionally-wrong-test-passphrase")
        try secrets.write(JSONEncoder().encode(credential), account: SSHTransport.credentialAccount(device))
        let pipeline = SSHConnectionPipeline(backend: UnexpectedConnectionBackend())

        do {
            _ = try await pipeline.connect(device: device, endpoint: endpoint, secrets: secrets, timeout: 5)
            XCTFail("An encrypted key with a wrong passphrase unexpectedly connected")
        } catch SSHFailure.invalidPrivateKey {}
    }

    func testRealOpenSSHHostVerificationAuthenticationPTYResizeAndExit() async throws {
        let environment = ProcessInfo.processInfo.environment
        guard let keyPath = environment["NEXUS_TEST_PRIVATE_KEY"], let username = environment["NEXUS_TEST_USER"] else {
            throw XCTSkip("Run bash scripts/test-openssh.sh on macOS to start the disposable loopback SSH fixture.")
        }
        let endpoint = Endpoint(host: "127.0.0.1", port: 22222)
        let device = Device(name: "Disposable OpenSSH", username: username, endpoints: [endpoint], authentication: .ed25519)
        let secrets = MemorySecrets()
        let credential = Credential(secret: try String(contentsOfFile: keyPath, encoding: .utf8),
            passphrase: environment["NEXUS_TEST_KEY_PASSPHRASE"] ?? "")
        try secrets.write(JSONEncoder().encode(credential), account: SSHTransport.credentialAccount(device))
        let transport = SSHTransport()
        var challenge: HostKeyChallenge?
        do {
            try await transport.run(device: device, endpoint: endpoint, secrets: secrets, timeout: 3,
                onConnected: { XCTFail("Untrusted host authenticated") }, onOutput: { _ in })
            XCTFail("Unknown host accepted")
        } catch let unknown as HostKeyChallenge { challenge = unknown }
        let observed = try XCTUnwrap(challenge)
        XCTAssertEqual(observed.fingerprint, environment["NEXUS_TEST_HOST_FINGERPRINT"])
        try HostKeyVerifier.approve(observed, secrets: secrets)
        let output = OutputBuffer()
        let completed = expectation(description: "SSH PTY completed")
        let task = Task {
            defer { completed.fulfill() }
            do {
                try await transport.run(device: device, endpoint: endpoint, secrets: secrets, timeout: 3,
                    onConnected: {
                        do {
                            try await transport.resize(columns: 100, rows: 40)
                            try await transport.send(Data("printf 'NEXUS_'; printf 'PTY_OK\\n'; stty size; exit\r".utf8))
                        } catch { XCTFail("PTY input/resize failed: \(error)") }
                    }, onOutput: { data in await output.append(data) })
            } catch { XCTFail("Trusted SSH session failed: \(error)") }
        }
        await fulfillment(of: [completed], timeout: 20)
        await transport.disconnect(); task.cancel(); await task.value
        let text = await output.text()
        XCTAssertTrue(text.contains("NEXUS_PTY_OK"), text)
        XCTAssertTrue(text.contains("40 100"), text)
    }

    func testConcurrentPTYIsolationAndReconnect() async throws {
        let environment = ProcessInfo.processInfo.environment
        guard let keyPath = environment["NEXUS_TEST_PRIVATE_KEY"],
              let username = environment["NEXUS_TEST_USER"] else {
            throw XCTSkip("Run bash scripts/test-openssh.sh to start the disposable SSH fixture.")
        }
        let endpoint = Endpoint(host: "127.0.0.1", port: 22222)
        let secrets = MemorySecrets()
        let key = try String(contentsOfFile: keyPath, encoding: .utf8)
        let credential = Credential(secret: key, passphrase: environment["NEXUS_TEST_KEY_PASSPHRASE"] ?? "")
        let first = Device(name: "Session A", username: username, endpoints: [endpoint])
        let second = Device(name: "Session B", username: username, endpoints: [endpoint])
        try secrets.write(JSONEncoder().encode(credential), account: SSHTransport.credentialAccount(first))
        try secrets.write(JSONEncoder().encode(credential), account: SSHTransport.credentialAccount(second))

        let transportA = SSHTransport()
        let transportB = SSHTransport()
        var firstContact: HostKeyChallenge?
        do {
            try await transportA.run(device: first, endpoint: endpoint, secrets: secrets, timeout: 5,
                onConnected: { XCTFail("Unknown fixture was trusted") }, onOutput: { _ in })
            XCTFail("Unknown fixture host key was accepted")
        } catch let challenge as HostKeyChallenge { firstContact = challenge }
        try HostKeyVerifier.approve(try XCTUnwrap(firstContact), secrets: secrets)
        async let outputA = runFixtureCommand("NEXUS_SESSION_A", device: first,
            transport: transportA, endpoint: endpoint, secrets: secrets, timeout: 5)
        async let outputB = runFixtureCommand("NEXUS_SESSION_B", device: second,
            transport: transportB, endpoint: endpoint, secrets: secrets, timeout: 5)
        let (resultA, resultB) = try await (outputA, outputB)
        XCTAssertTrue(resultA.contains("NEXUS_SESSION_A"), resultA)
        XCTAssertFalse(resultA.contains("NEXUS_SESSION_B"), resultA)
        XCTAssertTrue(resultB.contains("NEXUS_SESSION_B"), resultB)
        XCTAssertFalse(resultB.contains("NEXUS_SESSION_A"), resultB)

        let reconnected = try await runFixtureCommand("NEXUS_RECONNECTED", device: first,
            transport: transportA, endpoint: endpoint, secrets: secrets, timeout: 5)
        XCTAssertTrue(reconnected.contains("NEXUS_RECONNECTED"), reconnected)
    }

    func testReadOnlyMetricsCommandOverVerifiedOpenSSH() async throws {
        let environment = ProcessInfo.processInfo.environment
        guard let keyPath = environment["NEXUS_TEST_PRIVATE_KEY"],
              let username = environment["NEXUS_TEST_USER"] else {
            throw XCTSkip("Run bash scripts/test-openssh.sh to start the disposable SSH fixture.")
        }
        let endpoint = Endpoint(host: "127.0.0.1", port: 22222)
        let device = Device(name: "Disposable metrics fixture", username: username, endpoints: [endpoint])
        let secrets = MemorySecrets()
        let credential = Credential(secret: try String(contentsOfFile: keyPath, encoding: .utf8),
            passphrase: environment["NEXUS_TEST_KEY_PASSPHRASE"] ?? "")
        try secrets.write(JSONEncoder().encode(credential), account: SSHTransport.credentialAccount(device))
        let transport = SSHTransport()

        do {
            do {
                _ = try await transport.fetchMetrics(device: device, endpoint: endpoint,
                    secrets: secrets, timeout: 5)
                XCTFail("Metrics command accepted an untrusted host key")
            } catch let challenge as HostKeyChallenge {
                XCTAssertEqual(challenge.fingerprint, environment["NEXUS_TEST_HOST_FINGERPRINT"])
                try HostKeyVerifier.approve(challenge, secrets: secrets)
            }

            let snapshot = try await transport.fetchMetrics(device: device, endpoint: endpoint,
                secrets: secrets, timeout: 10)
            XCTAssertNotNil(snapshot.bootID)
            XCTAssertNotNil(snapshot.uptimeSeconds)
            XCTAssertGreaterThan(snapshot.logicalCPUCount ?? 0, 0)
            XCTAssertGreaterThan(snapshot.memoryTotalBytes ?? 0, 0)
            XCTAssertNotNil(snapshot.rootFilesystem)
            XCTAssertFalse(snapshot.nvidiaSMIAvailable)
            XCTAssertTrue(snapshot.nvidiaGPUs.isEmpty)
        } catch {
            await transport.disconnect()
            throw error
        }
        await transport.disconnect()
    }

    func testCommandTimeoutWrapperWorksOverOpenSSH() async throws {
        let environment = ProcessInfo.processInfo.environment
        guard let keyPath = environment["NEXUS_TEST_PRIVATE_KEY"],
              let username = environment["NEXUS_TEST_USER"] else {
            throw XCTSkip("Run bash scripts/test-openssh.sh to start the disposable SSH fixture.")
        }
        let endpoint = Endpoint(host: "127.0.0.1", port: 22222)
        let device = Device(name: "Disposable command fixture", username: username, endpoints: [endpoint])
        let secrets = MemorySecrets()
        let credential = Credential(secret: try String(contentsOfFile: keyPath, encoding: .utf8),
            passphrase: environment["NEXUS_TEST_KEY_PASSPHRASE"] ?? "")
        try secrets.write(JSONEncoder().encode(credential), account: SSHTransport.credentialAccount(device))
        let transport = CommandTransport()
        do {
            do {
                _ = try await transport.run("printf unexpected", useSudo: false,
                    device: device, endpoint: endpoint, secrets: secrets, timeout: 3)
                XCTFail("A command ran before host-key approval")
            } catch let challenge as HostKeyChallenge {
                XCTAssertEqual(challenge.fingerprint, environment["NEXUS_TEST_HOST_FINGERPRINT"])
                try HostKeyVerifier.approve(challenge, secrets: secrets)
            }

            let completed = try await transport.run("printf NEXUS_COMMAND_OK", useSudo: false,
                device: device, endpoint: endpoint, secrets: secrets, timeout: 5)
            XCTAssertEqual(completed.output, "NEXUS_COMMAND_OK")
            XCTAssertFalse(completed.timedOut)

            let timedOut = try await transport.run("sleep 10", useSudo: false,
                device: device, endpoint: endpoint, secrets: secrets, timeout: 3)
            XCTAssertTrue(timedOut.timedOut)
        } catch {
            await transport.disconnectAll()
            throw error
        }
        await transport.disconnectAll()
    }

    private func runFixtureCommand(_ marker: String, device: Device, transport: SSHTransport,
                                   endpoint: Endpoint, secrets: MemorySecrets,
                                   timeout: Int) async throws -> String {
        let output = OutputBuffer()
        try await transport.run(device: device, endpoint: endpoint, secrets: secrets, timeout: timeout,
            onConnected: {
                try? await transport.send(Data("printf '\(marker)'; exit\r".utf8))
            }, onOutput: { data in await output.append(data) })
        return await output.text()
    }

    func testRealOpenSSHSFTPListingTransfersLinksAndEditConflict() async throws {
        let environment = ProcessInfo.processInfo.environment
        guard let keyPath = environment["NEXUS_TEST_PRIVATE_KEY"],
              let username = environment["NEXUS_TEST_USER"],
              let fixturePath = environment["FIXTURE_DIR"] else {
            throw XCTSkip("Run bash scripts/test-openssh.sh to start the disposable loopback SSH fixture.")
        }

        let endpoint = Endpoint(host: "127.0.0.1", port: 22222)
        let device = Device(name: "Disposable OpenSSH SFTP", username: username,
            endpoints: [endpoint], authentication: .ed25519)
        let secrets = MemorySecrets()
        let credential = Credential(secret: try String(contentsOfFile: keyPath, encoding: .utf8),
            passphrase: environment["NEXUS_TEST_KEY_PASSPHRASE"] ?? "")
        try secrets.write(JSONEncoder().encode(credential), account: SSHTransport.credentialAccount(device))

        let fixtureRoot = URL(fileURLWithPath: fixturePath, isDirectory: true)
            .appendingPathComponent("sftp-root", isDirectory: true)
        try? FileManager.default.removeItem(at: fixtureRoot)
        let remoteDirectory = fixtureRoot.appendingPathComponent("folder", isDirectory: true)
        try FileManager.default.createDirectory(at: remoteDirectory, withIntermediateDirectories: true)
        let remoteText = remoteDirectory.appendingPathComponent("existing.txt")
        try Data("before-edit".utf8).write(to: remoteText)
        let remoteLink = fixtureRoot.appendingPathComponent("folder-link")
        try FileManager.default.createSymbolicLink(at: remoteLink, withDestinationURL: remoteDirectory)
        let remoteTextLink = remoteDirectory.appendingPathComponent("text-link")
        try FileManager.default.createSymbolicLink(at: remoteTextLink, withDestinationURL: remoteText)

        let localUpload = fixtureRoot.appendingPathComponent("upload-source.txt")
        try Data("uploaded-by-nexus".utf8).write(to: localUpload)
        let localDownload = fixtureRoot.appendingPathComponent("download-result.txt")
        let transport = SFTPTransport()

        do {
            do {
                try await transport.connect(device: device, endpoint: endpoint, secrets: secrets, timeout: 3)
                XCTFail("SFTP accepted an unknown host key")
            } catch let challenge as HostKeyChallenge {
                XCTAssertEqual(challenge.fingerprint, environment["NEXUS_TEST_HOST_FINGERPRINT"])
                try HostKeyVerifier.approve(challenge, secrets: secrets)
            }
            try await transport.connect(device: device, endpoint: endpoint, secrets: secrets, timeout: 3)

            let serviceTransport = ServiceTransport()
            let services = try await serviceTransport.listServices(device: device, endpoint: endpoint,
                secrets: secrets, timeout: 3)
            XCTAssertEqual(services.map(\.name), ["inactive-test.service", "nexus-test.service"])
            XCTAssertTrue(services.first { $0.name == "nexus-test.service" }?.isActive == true)
            let logs = try await serviceTransport.recentLogs(for: "nexus-test.service", device: device,
                endpoint: endpoint, secrets: secrets, timeout: 3)
            XCTAssertTrue(logs.contains("fixture journal entry"))
            let processes = try await serviceTransport.topProcesses(device: device, endpoint: endpoint,
                secrets: secrets, timeout: 3)
            XCTAssertEqual(processes.first?.command, "nexus process fixture")
            let inspection = try await serviceTransport.inspectSystem(device: device, endpoint: endpoint,
                secrets: secrets, timeout: 3)
            XCTAssertEqual(inspection.distribution, "NixOS")
            XCTAssertEqual(inspection.nixosVersion, "26.05-fixture")
            let restartOutput = try await serviceTransport.perform(.restart, on: "nexus-test.service", useSudo: false,
                device: device, endpoint: endpoint, secrets: secrets, timeout: 3)
            XCTAssertTrue(restartOutput.contains("fixture restart nexus-test.service"))
            XCTAssertEqual(try String(contentsOf: fixtureRoot.appendingPathComponent("systemctl-actions.log"),
                encoding: .utf8), "restart nexus-test.service\n")
            let dryBuild = try await serviceTransport.rebuildNixOS(.validate,
                flakeAttribute: "nixosConfigurations.fixture", device: device,
                endpoint: endpoint, secrets: secrets, timeout: 3)
            XCTAssertTrue(dryBuild.succeeded)
            XCTAssertTrue(dryBuild.output.contains("fixture nixos-rebuild dry-build"))
            let successfulSwitch = try await serviceTransport.rebuildNixOS(.switchSystem,
                flakeAttribute: "nixosConfigurations.fixture", device: device,
                endpoint: endpoint, secrets: secrets, timeout: 3)
            XCTAssertTrue(successfulSwitch.succeeded)
            let failedBuildMarker = fixtureRoot.appendingPathComponent("fail-dry-build")
            try Data().write(to: failedBuildMarker)
            let blockedSwitch = try await serviceTransport.rebuildNixOS(.switchSystem,
                flakeAttribute: "nixosConfigurations.fixture", device: device,
                endpoint: endpoint, secrets: secrets, timeout: 3)
            XCTAssertFalse(blockedSwitch.succeeded)
            XCTAssertEqual(blockedSwitch.exitCode, 23)
            XCTAssertTrue(blockedSwitch.output.contains("fixture dry-build failed"))
            let rebuildCalls = try String(contentsOf: fixtureRoot.appendingPathComponent("nixos-rebuild-actions.log"),
                encoding: .utf8).split(whereSeparator: \.isNewline).map(String.init)
            XCTAssertEqual(rebuildCalls, [
                "nixos-rebuild dry-build --flake /etc/nixos#nixosConfigurations.fixture",
                "nixos-rebuild dry-build --flake /etc/nixos#nixosConfigurations.fixture",
                "nixos-rebuild switch --flake /etc/nixos#nixosConfigurations.fixture",
                "nixos-rebuild dry-build --flake /etc/nixos#nixosConfigurations.fixture"
            ])

            let listing = try await transport.listDirectory(at: fixtureRoot.path)
            let folder = try XCTUnwrap(listing.first { $0.name == "folder-link" })
            XCTAssertTrue(folder.isSymbolicLink)
            XCTAssertTrue(folder.isDirectory)
            XCTAssertEqual(folder.resolvedTargetPath, remoteDirectory.path)

            let symlinkListing = try await transport.listDirectory(at: remoteDirectory.path)
            let textLinkEntry = try XCTUnwrap(symlinkListing.first { $0.name == "text-link" })
            XCTAssertTrue(textLinkEntry.isSymbolicLink)
            XCTAssertFalse(textLinkEntry.isDirectory)
            let resolvedTextPath = try XCTUnwrap(textLinkEntry.resolvedTargetPath)
            let linkedContents = try await transport.readTextFile(at: resolvedTextPath)
            XCTAssertEqual(linkedContents.0, "before-edit")
            let linkedDownload = fixtureRoot.appendingPathComponent("linked-download.txt")
            try await transport.download(remotePath: resolvedTextPath, to: linkedDownload)
            XCTAssertEqual(try String(contentsOf: linkedDownload, encoding: .utf8), "before-edit")
            let linkedPreview = try await transport.readTextFile(at: resolvedTextPath)
            try await transport.saveTextFile("saved-through-link", at: resolvedTextPath,
                expectedSize: linkedPreview.1, expectedModifiedAt: linkedPreview.2)
            XCTAssertEqual(try String(contentsOf: remoteTextLink, encoding: .utf8), "saved-through-link")
            XCTAssertEqual(try FileManager.default.destinationOfSymbolicLink(atPath: remoteTextLink.path),
                remoteText.path)
            try Data("before-edit".utf8).write(to: remoteText)

            let permissionFile = remoteDirectory.appendingPathComponent("permissions.txt")
            try Data("permission fixture".utf8).write(to: permissionFile)
            try FileManager.default.setAttributes([.posixPermissions: 0o640],
                ofItemAtPath: permissionFile.path)
            let permissionListing = try await transport.listDirectory(at: remoteDirectory.path)
            let permissionEntry = try XCTUnwrap(permissionListing.first { $0.name == "permissions.txt" })
            XCTAssertEqual(permissionEntry.permissions.map { $0 & 0o777 }, 0o640)
            try await transport.setPermissions(at: permissionFile.path, accessMode: 0o604)
            let updatedFileMode = try XCTUnwrap(
                FileManager.default.attributesOfItem(atPath: permissionFile.path)[.posixPermissions] as? NSNumber
            ).uint32Value
            XCTAssertEqual(updatedFileMode & 0o777, 0o604)

            try FileManager.default.setAttributes([.posixPermissions: 0o750],
                ofItemAtPath: remoteDirectory.path)
            try await transport.setPermissions(at: remoteDirectory.path, accessMode: 0o710)
            let updatedDirectoryMode = try XCTUnwrap(
                FileManager.default.attributesOfItem(atPath: remoteDirectory.path)[.posixPermissions] as? NSNumber
            ).uint32Value
            XCTAssertEqual(updatedDirectoryMode & 0o777, 0o710)

            do {
                try await transport.setPermissions(at: remoteLink.path, accessMode: 0o700)
                XCTFail("SFTP changed the permissions through a symbolic link")
            } catch SFTPTransportError.symbolicLinkTarget {}

            let remoteUpload = remoteDirectory.appendingPathComponent("uploaded.txt").path
            try await transport.upload(localURL: localUpload, to: remoteUpload, overwrite: false)
            let downloadedContent = try await transport.readTextFile(at: remoteUpload)
            XCTAssertEqual(downloadedContent.0, "uploaded-by-nexus")

            let cancellationSource = fixtureRoot.appendingPathComponent("cancel-upload.bin")
            try Data(repeating: 0x43, count: 256 * 1024).write(to: cancellationSource)
            let cancelledRemotePath = remoteDirectory.appendingPathComponent("cancelled-upload.bin").path
            let uploadTask = Task {
                try await transport.upload(localURL: cancellationSource, to: cancelledRemotePath,
                    overwrite: false) { transferred, _ in
                    if transferred > 0 { withUnsafeCurrentTask { $0?.cancel() } }
                }
            }
            do {
                try await uploadTask.value
                XCTFail("SFTP upload ignored task cancellation")
            } catch is CancellationError {
                let afterCancellation = try await transport.listDirectory(at: remoteDirectory.path)
                XCTAssertFalse(afterCancellation.contains { $0.name == "cancelled-upload.bin" })
                XCTAssertFalse(afterCancellation.contains { $0.name.hasPrefix(".nexus-upload-") })
            }

            let overwriteTarget = remoteDirectory.appendingPathComponent("overwrite-target.txt")
            try Data("before-overwrite".utf8).write(to: overwriteTarget)
            let overwriteListing = try await transport.listDirectory(at: remoteDirectory.path)
            let overwriteEntry = try XCTUnwrap(overwriteListing.first { $0.name == "overwrite-target.txt" })
            try await transport.upload(localURL: localUpload, to: overwriteTarget.path, overwrite: true,
                expectedExistingSize: overwriteEntry.size,
                expectedExistingModifiedAt: overwriteEntry.modifiedAt)
            XCTAssertEqual(try String(contentsOf: overwriteTarget, encoding: .utf8), "uploaded-by-nexus")

            let appearingSource = fixtureRoot.appendingPathComponent("appearing-destination-source.bin")
            try Data(repeating: 0x45, count: 256 * 1024).write(to: appearingSource)
            let appearingDestination = remoteDirectory.appendingPathComponent("appeared-during-upload.txt")
            do {
                try await transport.upload(localURL: appearingSource, to: appearingDestination.path,
                    overwrite: false) { transferred, _ in
                    if transferred > 0 { try? Data("created by another writer".utf8).write(to: appearingDestination) }
                }
                XCTFail("SFTP replaced a destination created by another writer during upload")
            } catch SFTPTransportError.remotePathAlreadyExists {
                XCTAssertEqual(try String(contentsOf: appearingDestination, encoding: .utf8),
                    "created by another writer")
                let afterRace = try await transport.listDirectory(at: remoteDirectory.path)
                XCTAssertFalse(afterRace.contains { $0.name.hasPrefix(".nexus-upload-") })
            }

            let changingTarget = remoteDirectory.appendingPathComponent("changed-overwrite-target.txt")
            try Data("original-target".utf8).write(to: changingTarget)
            let changingTargetListing = try await transport.listDirectory(at: remoteDirectory.path)
            let changingTargetEntry = try XCTUnwrap(changingTargetListing.first {
                $0.name == "changed-overwrite-target.txt"
            })
            let overwriteSource = fixtureRoot.appendingPathComponent("overwrite-source.bin")
            try Data(repeating: 0x46, count: 256 * 1024).write(to: overwriteSource)
            do {
                try await transport.upload(localURL: overwriteSource, to: changingTarget.path, overwrite: true,
                    expectedExistingSize: changingTargetEntry.size,
                    expectedExistingModifiedAt: changingTargetEntry.modifiedAt) { transferred, _ in
                    if transferred > 0 { try? Data("changed by another writer".utf8).write(to: changingTarget) }
                }
                XCTFail("SFTP overwrote a destination changed by another writer during transfer")
            } catch SFTPTransportError.remoteFileChanged {
                XCTAssertEqual(try String(contentsOf: changingTarget, encoding: .utf8),
                    "changed by another writer")
                let afterRace = try await transport.listDirectory(at: remoteDirectory.path)
                XCTAssertFalse(afterRace.contains { $0.name.hasPrefix(".nexus-upload-") })
            }

            let changingSource = fixtureRoot.appendingPathComponent("changing-source.bin")
            let originalBytes = Data(repeating: 0x41, count: 256 * 1024)
            let replacementBytes = Data(repeating: 0x42, count: originalBytes.count)
            try originalBytes.write(to: changingSource)
            let changingDestination = remoteDirectory.appendingPathComponent("changed-during-upload.bin").path
            do {
                try await transport.upload(localURL: changingSource, to: changingDestination, overwrite: false) {
                    transferred, _ in
                    if transferred == 128 * 1024 {
                        try? replacementBytes.write(to: changingSource)
                    }
                }
                XCTFail("SFTP published a mixed snapshot after the local source changed during transfer")
            } catch SFTPTransportError.localFileChanged {
                let afterMutation = try await transport.listDirectory(at: remoteDirectory.path)
                XCTAssertFalse(afterMutation.contains { $0.name == "changed-during-upload.bin" })
            }

            do {
                try await transport.upload(localURL: localUpload,
                    to: remoteLink.path, overwrite: false)
                XCTFail("SFTP replaced a symbolic link")
            } catch SFTPTransportError.symbolicLinkTarget {
                XCTAssertEqual(try String(contentsOf: remoteDirectory.appendingPathComponent("existing.txt"),
                    encoding: .utf8), "before-edit")
            }

            try await transport.download(remotePath: remoteUpload, to: localDownload)
            XCTAssertEqual(try Data(contentsOf: localDownload), Data("uploaded-by-nexus".utf8))

            let largeRemoteFile = remoteDirectory.appendingPathComponent("cancel-download.bin")
            try Data(repeating: 0x44, count: 256 * 1024).write(to: largeRemoteFile)
            let cancelledLocalPath = fixtureRoot.appendingPathComponent("cancelled-download.bin")
            let downloadTask = Task {
                try await transport.download(remotePath: largeRemoteFile.path, to: cancelledLocalPath) { transferred, _ in
                    if transferred > 0 { withUnsafeCurrentTask { $0?.cancel() } }
                }
            }
            do {
                try await downloadTask.value
                XCTFail("SFTP download ignored task cancellation")
            } catch is CancellationError {
                XCTAssertFalse(FileManager.default.fileExists(atPath: cancelledLocalPath.path))
            }

            let preview = try await transport.readTextFile(at: remoteText.path)
            try Data("changed-elsewhere".utf8).write(to: remoteText)
            do {
                try await transport.saveTextFile("should-not-overwrite", at: remoteText.path,
                    expectedSize: preview.1, expectedModifiedAt: preview.2)
                XCTFail("SFTP overwrote a file changed after preview")
            } catch SFTPTransportError.remoteFileChanged {
                XCTAssertEqual(try String(contentsOf: remoteText, encoding: .utf8), "changed-elsewhere")
            }
        } catch {
            await transport.disconnect()
            throw error
        }
        await transport.disconnect()
    }
}

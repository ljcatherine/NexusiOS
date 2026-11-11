import XCTest
import NexusCore
@testable import NexusSSH

final class TransportFailureTests: XCTestCase {
    func testMissingCredentialFailsBeforeConnecting() async throws {
        let endpoint = Endpoint(host: "127.0.0.1", port: 1)
        let device = Device(name: "Fixture", username: "fixture", endpoints: [endpoint])
        let transport = SSHTransport()
        do {
            try await transport.run(device: device, endpoint: endpoint, secrets: MemorySecrets(), timeout: 3,
                onConnected: { XCTFail("Connected without credential") }, onOutput: { _ in })
            XCTFail("Accepted missing credential")
        } catch SSHFailure.missingCredential {} catch { XCTFail("Unexpected error: \(error)") }
    }
    func testMalformedPrivateKeyFailsWithoutDisclosingInput() async throws {
        let endpoint = Endpoint(host: "127.0.0.1", port: 1)
        let device = Device(name: "Fixture", username: "fixture", endpoints: [endpoint], authentication: .ed25519)
        let secrets = MemorySecrets()
        let sensitiveFixture = "malformed-private-key-fixture"
        try secrets.write(JSONEncoder().encode(Credential(secret: sensitiveFixture)), account: SSHTransport.credentialAccount(device))
        do {
            try await SSHTransport().run(device: device, endpoint: endpoint, secrets: secrets, timeout: 3,
                onConnected: { XCTFail("Connected with malformed key") }, onOutput: { _ in })
            XCTFail("Accepted malformed key")
        } catch SSHFailure.invalidPrivateKey {
            XCTAssertFalse(SSHFailure.invalidPrivateKey.localizedDescription.contains(sensitiveFixture))
        } catch { XCTFail("Unexpected error: \(error)") }
    }
}

import XCTest
import Citadel
import NIO
import NIOSSH
import NexusCore
@testable import NexusSSH

private actor ConnectionAttemptCounter {
    private(set) var value = 0
    func increment() { value += 1 }
}

private struct NeverConnectBackend: SSHConnectionBackend {
    let counter: ConnectionAttemptCounter
    func connect(settings: SSHClientSettings) async throws -> SSHClient {
        await counter.increment()
        throw SSHFailure.connectionFailed
    }
}

final class SSHConnectionPipelineTests: XCTestCase {
    func testGeneratedEd25519KeyPairParsesAndMatches() throws {
        let pair = try SSHKeyGenerator.generate(comment: "nexus-test-key")
        let device = Device(name: "Fixture", username: "fixture", endpoints: [Endpoint(host: "server.example")])

        XCTAssertNoThrow(try SSHTransport.validateCredential(for: device, credential: Credential(secret: pair.privateKey)))
        let parsedPublicKey = try NIOSSHPublicKey(openSSHPublicKey: pair.publicKey)
        let canonicalPublicKey = String(openSSHPublicKey: parsedPublicKey)
        XCTAssertEqual(canonicalPublicKey.split(separator: " ").prefix(2), pair.publicKey.split(separator: " ").prefix(2))
        XCTAssertTrue(pair.privateKey.hasPrefix("-----BEGIN OPENSSH PRIVATE KEY-----\n"))
        XCTAssertFalse(pair.privateKey.contains("nexus-test-key"))
    }

    func testGeneratedEd25519KeyRejectsUnsafeComments() {
        XCTAssertThrowsError(try SSHKeyGenerator.generate(comment: "bad\ncomment"))
        XCTAssertThrowsError(try SSHKeyGenerator.generate(comment: String(repeating: "x", count: 257)))
    }

    func testPrivateKeyTextNormalizesLineEndingsAndRejectsNonOpenSSHInput() throws {
        let input = "-----BEGIN OPENSSH PRIVATE KEY-----\r\nYWJj\r\n-----END OPENSSH PRIVATE KEY-----\r\n"
        XCTAssertEqual(try SSHPrivateKeyFile.normalize(input),
            "-----BEGIN OPENSSH PRIVATE KEY-----\nYWJj\n-----END OPENSSH PRIVATE KEY-----\n")
        XCTAssertThrowsError(try SSHPrivateKeyFile.normalize("sensitive-invalid-key"))
        XCTAssertThrowsError(try SSHPrivateKeyFile.normalize(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n%%%\n-----END OPENSSH PRIVATE KEY-----"))
    }

    func testOversizedKeyAndPassphraseAreRejectedLocally() throws {
        let endpoint = Endpoint(host: "server.example")
        let device = Device(name: "Fixture", username: "fixture", endpoints: [endpoint])
        XCTAssertThrowsError(try SSHTransport.authentication(device: device,
            credential: Credential(secret: String(repeating: "x", count: SSHPrivateKeyFile.maximumBytes + 1))))
    }

    func testMissingCredentialNeverInvokesNetworkBackend() async throws {
        let counter = ConnectionAttemptCounter()
        let pipeline = SSHConnectionPipeline(backend: NeverConnectBackend(counter: counter))
        let endpoint = Endpoint(host: "127.0.0.1", port: 22)
        let device = Device(name: "Fixture", username: "fixture", endpoints: [endpoint])
        do {
            _ = try await pipeline.connect(device: device, endpoint: endpoint,
                secrets: MemorySecrets(), timeout: 3)
            XCTFail("Connected without a key")
        } catch SSHFailure.missingCredential {}
        let attempts = await counter.value
        XCTAssertEqual(attempts, 0)
    }

    func testExampleEndpointIsRejectedBeforeCredentialLookupOrNetwork() async throws {
        let counter = ConnectionAttemptCounter()
        let pipeline = SSHConnectionPipeline(backend: NeverConnectBackend(counter: counter))
        let endpoint = Endpoint(host: "NixOS.Example.Invalid")
        let device = Device(name: "Example", username: "user", endpoints: [endpoint])
        do {
            _ = try await pipeline.connect(device: device, endpoint: endpoint,
                secrets: MemorySecrets(), timeout: 3)
            XCTFail("A reserved example endpoint must never connect")
        } catch SSHFailure.exampleEndpoint {}
        let attempts = await counter.value
        XCTAssertEqual(attempts, 0)
    }

    func testFallbackIsRestrictedToReachabilityFailures() {
        XCTAssertTrue(SSHFailure.connectionFailed.allowsEndpointFallback)
        XCTAssertTrue(SSHFailure.connectionTimedOut.allowsEndpointFallback)
        XCTAssertFalse(SSHFailure.trustedEndpointHandshakeFailed.allowsEndpointFallback)
        XCTAssertFalse(SSHFailure.invalidPrivateKey.allowsEndpointFallback)
        XCTAssertFalse(SSHFailure.changedHostKey.allowsEndpointFallback)
        XCTAssertFalse(SSHFailure.metricsCommandTimedOut.allowsEndpointFallback)
        XCTAssertFalse(SSHFailure.metricsCommandFailed.allowsEndpointFallback)
        XCTAssertFalse(SSHFailure.invalidMetricsResponse.allowsEndpointFallback)
        XCTAssertFalse(SSHFailure.missingCredential.allowsEndpointFallback)
        XCTAssertFalse(SSHFailure.authenticationRejected.allowsEndpointFallback)
        XCTAssertFalse(SSHFailure.publicKeyAuthenticationUnavailable.allowsEndpointFallback)
    }

    func testCopiedSSHDiagnosticExcludesArbitraryNSErrorText() {
        let sensitiveValue = "private-hostname-and-user-fixture"
        let leaf = NSError(domain: sensitiveValue, code: 71,
            userInfo: [NSLocalizedDescriptionKey: sensitiveValue])
        let root = NSError(domain: "outer-\(sensitiveValue)", code: 72,
            userInfo: [NSUnderlyingErrorKey: leaf, NSLocalizedDescriptionKey: sensitiveValue])

        let diagnostic = SSHDiagnosticFormatter.describe(root)

        XCTAssertTrue(diagnostic.contains("code 72"))
        XCTAssertTrue(diagnostic.contains("code 71"))
        XCTAssertFalse(diagnostic.contains(sensitiveValue))
        XCTAssertFalse(diagnostic.contains("outer-"))
        XCTAssertLessThanOrEqual(diagnostic.components(separatedBy: " ← ").count, 4)
    }

    func testCopiedSSHDiagnosticNamesMappedFailureWithoutLeakingErrorText() {
        let diagnostic = SSHDiagnosticFormatter.describe(SSHFailure.connectionFailed)

        XCTAssertTrue(diagnostic.contains("connectionFailed"))
        XCTAssertTrue(diagnostic.contains("code 5"))
        XCTAssertFalse(diagnostic.contains("SSH connection failed."))
    }

    func testProtocolErrorNameUsesOnlyStaticNIOSSHErrorType() {
        XCTAssertEqual(SSHDiagnosticFormatter.protocolErrorName(.keyExchangeNegotiationFailure),
            "keyExchangeNegotiationFailure")
        XCTAssertEqual(SSHDiagnosticFormatter.protocolErrorName(.protocolViolation), "protocolViolation")
    }

    func testHandshakeErrorsAreClassifiedWithoutSurfacingDependencyDetails() {
        XCTAssertEqual(SSHConnectionPipeline.classifyHandshakeError(SSHClientError.allAuthenticationOptionsFailed),
            .authenticationRejected)
        XCTAssertEqual(SSHConnectionPipeline.classifyHandshakeError(SSHClientError.unsupportedPrivateKeyAuthentication),
            .publicKeyAuthenticationUnavailable)
        XCTAssertEqual(SSHConnectionPipeline.classifyHandshakeError(ChannelError.connectTimeout(.seconds(10))),
            .connectionTimedOut)
        XCTAssertEqual(SSHConnectionPipeline.classifyHandshakeError(
            IOError(errnoCode: Int32(POSIXErrorCode.ECONNREFUSED.rawValue), reason: "private socket detail")),
            .connectionRefused)
        XCTAssertEqual(SSHConnectionPipeline.classifyHandshakeError(
            IOError(errnoCode: Int32(POSIXErrorCode.ENETUNREACH.rawValue), reason: "private socket detail")),
            .networkUnreachable)
        XCTAssertEqual(SSHConnectionPipeline.classifyHandshakeError(
            IOError(errnoCode: Int32(POSIXErrorCode.EHOSTUNREACH.rawValue), reason: "private socket detail")),
            .networkUnreachable)
        XCTAssertEqual(SSHConnectionPipeline.classifyHandshakeError(
            IOError(errnoCode: Int32(POSIXErrorCode.ETIMEDOUT.rawValue), reason: "private socket detail")),
            .connectionTimedOut)
        XCTAssertTrue(SSHFailure.endpointNameResolutionFailed.allowsEndpointFallback)
        XCTAssertTrue(SSHFailure.connectionRefused.allowsEndpointFallback)
        XCTAssertTrue(SSHFailure.networkUnreachable.allowsEndpointFallback)
        XCTAssertFalse(SSHFailure.connectionRefused.localizedDescription.contains("private-host"))
        XCTAssertFalse(SSHFailure.networkUnreachable.localizedDescription.contains("private socket detail"))

        let rejected = SSHFailure.authenticationRejected.localizedDescription
        XCTAssertTrue(rejected.contains("matching public key"))
        XCTAssertFalse(rejected.contains("passphrase"))
        XCTAssertFalse(rejected.contains("192.168."))
    }
}

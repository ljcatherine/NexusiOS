import NIOCore
import NIOEmbedded
@testable import NIOSSH
import Citadel
import XCTest

private struct RejectAuthentication: NIOSSHClientUserAuthenticationDelegate {
    func nextAuthenticationType(availableMethods: NIOSSHAvailableUserAuthenticationMethods,
                                nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>) {
        nextChallengePromise.fail(SSHNegotiationTestError.unexpectedAuthentication)
    }
}

private struct RejectHostKey: NIOSSHClientServerAuthenticationDelegate {
    func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
        validationCompletePromise.fail(SSHNegotiationTestError.unexpectedHostKeyValidation)
    }
}

private enum SSHNegotiationTestError: Error {
    case unexpectedAuthentication
    case unexpectedHostKeyValidation
}

final class SSHNegotiationTests: XCTestCase {
    func testAESGCMIgnoresDisjointDirectionalEtMMacLists() throws {
        let schemes: [NIOSSHTransportProtection.Type] = [
            AES256GCMOpenSSHTransportProtection.self,
            AES128GCMOpenSSHTransportProtection.self
        ]

        for scheme in schemes {
            var client = makeClient(schemes: schemes)
            let clientProposal = client.createKeyExchangeMessage()
            var serverProposal = clientProposal
            serverProposal.keyExchangeAlgorithms = ["curve25519-sha256"]
            serverProposal.serverHostKeyAlgorithms = ["ssh-ed25519"]
            serverProposal.encryptionAlgorithmsClientToServer = [Substring(scheme.cipherName)]
            serverProposal.encryptionAlgorithmsServerToClient = [Substring(scheme.cipherName)]
            serverProposal.macAlgorithmsClientToServer = ["hmac-sha2-256-etm@openssh.com"]
            serverProposal.macAlgorithmsServerToClient = ["hmac-sha2-512-etm@openssh.com"]
            client.send(keyExchange: clientProposal)

            let response = try client.handle(keyExchange: serverProposal)
            guard let response, response.count == 1, case .keyExchangeInit = response.first else {
                XCTFail("AES-GCM negotiation did not produce the expected key exchange init")
                continue
            }
        }
    }

    func testNonAEADCipherStillRequiresSharedMac() {
        let schemes: [NIOSSHTransportProtection.Type] = [AES128CTR.self]
        var client = makeClient(schemes: schemes)
        let clientProposal = client.createKeyExchangeMessage()
        var serverProposal = clientProposal
        serverProposal.keyExchangeAlgorithms = ["curve25519-sha256"]
        serverProposal.serverHostKeyAlgorithms = ["ssh-ed25519"]
        serverProposal.encryptionAlgorithmsClientToServer = ["aes128-ctr"]
        serverProposal.encryptionAlgorithmsServerToClient = ["aes128-ctr"]
        serverProposal.macAlgorithmsClientToServer = ["hmac-sha2-256-etm@openssh.com"]
        serverProposal.macAlgorithmsServerToClient = ["hmac-sha2-256-etm@openssh.com"]
        client.send(keyExchange: clientProposal)

        XCTAssertThrowsError(try client.handle(keyExchange: serverProposal))

        serverProposal.macAlgorithmsClientToServer = ["hmac-sha2-256"]
        serverProposal.macAlgorithmsServerToClient = ["hmac-sha2-256"]
        var compatibleClient = makeClient(schemes: schemes)
        let compatibleProposal = compatibleClient.createKeyExchangeMessage()
        compatibleClient.send(keyExchange: compatibleProposal)
        XCTAssertNoThrow(try compatibleClient.handle(keyExchange: serverProposal))
    }

    private func makeClient(schemes: [NIOSSHTransportProtection.Type]) -> SSHKeyExchangeStateMachine {
        var configuration = SSHClientConfiguration(
            userAuthDelegate: RejectAuthentication(),
            serverAuthDelegate: RejectHostKey()
        )
        configuration.transportProtectionSchemes = schemes
        return SSHKeyExchangeStateMachine(
            allocator: ByteBufferAllocator(),
            loop: EmbeddedEventLoop(),
            role: .client(configuration),
            remoteVersion: "SSH-2.0-nexus-test",
            keyExchangeAlgorithms: SSHKeyExchangeStateMachine.bundledKeyExchangeImplementations,
            transportProtectionSchemes: schemes,
            previousSessionIdentifier: nil
        )
    }
}

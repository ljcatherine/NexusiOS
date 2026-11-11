import XCTest
import Crypto
import NIO
import NIOSSH
import NexusCore
@testable import NexusSSH

final class MemorySecrets: SecretStore, @unchecked Sendable {
    private let lock = NSLock()
    private var data: [String: Data] = [:]
    func read(_ account: String) throws -> Data? { lock.lock(); defer { lock.unlock() }; return data[account] }
    func write(_ value: Data, account: String) throws { lock.lock(); defer { lock.unlock() }; data[account] = value }
    func delete(_ account: String) throws { lock.lock(); defer { lock.unlock() }; data.removeValue(forKey: account) }
}

final class HostKeyTests: XCTestCase {
    func testFirstContactAndOutOfBandVerifiedHostKeyRotation() async throws {
        let secrets = MemorySecrets()
        let endpoint = Endpoint(host: "server.example")
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { try? group.syncShutdownGracefully() }
        let key = NIOSSHPrivateKey(ed25519Key: Curve25519.Signing.PrivateKey()).publicKey
        let verifier = HostKeyVerifier(endpoint: endpoint, secrets: secrets)
        let first = group.next().makePromise(of: Void.self)
        verifier.validateHostKey(hostKey: key, validationCompletePromise: first)
        do { try await first.futureResult.get(); XCTFail("Unknown host accepted") } catch {}
        XCTAssertNil(try secrets.read(HostKeyVerifier.account(endpoint)))
        let challenge = try XCTUnwrap(verifier.challenge)
        XCTAssertFalse(challenge.changed)
        XCTAssertTrue(challenge.fingerprint.hasPrefix("SHA256:"))
        try HostKeyVerifier.approve(challenge, secrets: secrets)
        let trusted = group.next().makePromise(of: Void.self)
        verifier.validateHostKey(hostKey: key, validationCompletePromise: trusted)
        try await trusted.futureResult.get()
        let rotatedKey = NIOSSHPrivateKey(ed25519Key: Curve25519.Signing.PrivateKey()).publicKey
        let changedVerifier = HostKeyVerifier(endpoint: endpoint, secrets: secrets)
        let changed = group.next().makePromise(of: Void.self)
        changedVerifier.validateHostKey(hostKey: rotatedKey, validationCompletePromise: changed)
        do { try await changed.futureResult.get(); XCTFail("Changed host accepted") } catch {}
        let changedChallenge = try XCTUnwrap(changedVerifier.challenge)
        XCTAssertTrue(changedChallenge.changed)
        XCTAssertThrowsError(try HostKeyVerifier.approve(changedChallenge, secrets: secrets))
        let originalFingerprint = try HostKeyVerifier.fingerprint(String(openSSHPublicKey: key))
        XCTAssertEqual(changedChallenge.previousFingerprint, originalFingerprint)
        XCTAssertThrowsError(try HostKeyVerifier.replace(changedChallenge,
            confirmedFingerprint: "SHA256:not-the-new-key", secrets: secrets))
        let account = HostKeyVerifier.account(endpoint)
        let originalKey = Data(String(openSSHPublicKey: key).utf8)
        XCTAssertEqual(try secrets.read(account), originalKey)
        let concurrentKey = NIOSSHPrivateKey(ed25519Key: Curve25519.Signing.PrivateKey()).publicKey
        let concurrentPublicKey = String(openSSHPublicKey: concurrentKey)
        try secrets.write(Data(concurrentPublicKey.utf8), account: account)
        XCTAssertThrowsError(try HostKeyVerifier.replace(changedChallenge,
            confirmedFingerprint: changedChallenge.fingerprint, secrets: secrets))
        XCTAssertEqual(try secrets.read(account), Data(concurrentPublicKey.utf8))
        try secrets.write(originalKey, account: account)
        try HostKeyVerifier.replace(changedChallenge,
            confirmedFingerprint: changedChallenge.fingerprint, secrets: secrets)
        let rotated = group.next().makePromise(of: Void.self)
        changedVerifier.validateHostKey(hostKey: rotatedKey, validationCompletePromise: rotated)
        try await rotated.futureResult.get()
        let oldKeyRejected = group.next().makePromise(of: Void.self)
        changedVerifier.validateHostKey(hostKey: key, validationCompletePromise: oldKeyRejected)
        do { try await oldKeyRejected.futureResult.get(); XCTFail("Old host key remained trusted after rotation") } catch {}
    }
    func testKeychainRoundTripAndDeletion() throws {
#if canImport(Security)
        let store = KeychainStore(service: "NexusTests." + UUID().uuidString)
        defer { try? store.delete("fixture") }
        XCTAssertNil(try store.read("fixture"))
        try store.write(Data("first".utf8), account: "fixture")
        try store.write(Data("replacement".utf8), account: "fixture")
        XCTAssertEqual(try store.read("fixture"), Data("replacement".utf8))
        try store.delete("fixture"); XCTAssertNil(try store.read("fixture"))
#else
        XCTAssertThrowsError(try KeychainStore().read("fixture"))
#endif
    }
}

import Crypto
import Foundation
import NIO
import NIOEmbedded
import NIOSSH
import XCTest
@testable import NexusSSH

private struct NoAuthentication: NIOSSHClientUserAuthenticationDelegate {
    func nextAuthenticationType(availableMethods: NIOSSHAvailableUserAuthenticationMethods,
                                nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>) {
        nextChallengePromise.succeed(nil)
    }
}

private struct NoHostKeyValidation: NIOSSHClientServerAuthenticationDelegate {
    func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
        validationCompletePromise.fail(ChannelError.eof)
    }
}

final class CloudflareSSHUpgradeTests: XCTestCase {
    private func makeUpgradedChannel() throws -> EmbeddedChannel {
        let channel = EmbeddedChannel()
        let upgrade = UpgradeState()
        let ready = channel.eventLoop.makePromise(of: Void.self)
        upgrade.install(ready)
        try CloudflareSSHConnector.configureUpgrade(channel: channel, host: "relay.invalid",
            path: "/v1/ssh/debian", token: "fixture", upgrade: upgrade).wait()
        try channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 443)).wait()

        var request = ""
        while var part = try channel.readOutbound(as: ByteBuffer.self) {
            request += part.readString(length: part.readableBytes) ?? ""
        }
        let keyLine = try XCTUnwrap(request.components(separatedBy: "\r\n").first {
            $0.lowercased().hasPrefix("sec-websocket-key:")
        })
        let key = keyLine.split(separator: ":", maxSplits: 1)[1].trimmingCharacters(in: .whitespaces)
        let accept = Data(Insecure.SHA1.hash(data: Data((key +
            "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").utf8))).base64EncodedString()
        let response = "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: \(accept)\r\nSec-WebSocket-Protocol: nexus-ssh-v1\r\n\r\n"
        try channel.writeInbound(channel.allocator.buffer(string: response))
        channel.embeddedEventLoop.run()
        try ready.futureResult.wait()
        return channel
    }

    func testUnexpectedOutboundTypeFailsClosedBeforeWebSocketFrameEncoder() throws {
        let channel = try makeUpgradedChannel()
        defer { _ = try? channel.finish() }

        // Previously the catch-all forwarding path passed this non-frame into
        // WebSocketFrameEncoder, whose force-cast can trap the process.
        XCTAssertThrowsError(try channel.writeOutbound(42))
        channel.embeddedEventLoop.run()
        XCTAssertFalse(channel.isActive, "A broken transport type contract must close the connection")
    }

    func testWebSocketPingReceivesMaskedPongWithoutSSHEnvelope() throws {
        let channel = try makeUpgradedChannel()
        defer { _ = try? channel.finish() }

        var ping = channel.allocator.buffer(capacity: 5)
        ping.writeBytes([0x89, 0x03, 0x61, 0x62, 0x63])
        try channel.writeInbound(ping)
        channel.embeddedEventLoop.run()

        var wire: [UInt8] = []
        while var part = try channel.readOutbound(as: ByteBuffer.self) {
            wire += part.readBytes(length: part.readableBytes) ?? []
        }
        XCTAssertGreaterThanOrEqual(wire.count, 9)
        guard wire.count >= 9 else { return }
        XCTAssertEqual(wire[0], 0x8A, "A ping must be acknowledged as a pong frame")
        XCTAssertEqual(wire[1], 0x83, "Client pong must be masked")
        let mask = Array(wire[2..<6])
        let payload = wire[6..<9].enumerated().map { $0.element ^ mask[$0.offset % 4] }
        XCTAssertEqual(payload, Array("abc".utf8))
    }

    func testHTTPAuthorizationFailureDoesNotMarkSSHReady() throws {
        let channel = EmbeddedChannel()
        defer { _ = try? channel.finish() }
        let upgrade = UpgradeState()
        let ready = channel.eventLoop.makePromise(of: Void.self)
        upgrade.install(ready)
        try CloudflareSSHConnector.configureUpgrade(channel: channel, host: "relay.invalid",
            path: "/v1/ssh/debian", token: "fixture", upgrade: upgrade).wait()
        try channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 443)).wait()

        while let _ = try channel.readOutbound(as: ByteBuffer.self) {}
        try channel.writeInbound(channel.allocator.buffer(string:
            "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n"))
        channel.embeddedEventLoop.run()
        XCTAssertThrowsError(try ready.futureResult.wait(),
            "An Access denial must fail the upgrade before Citadel installs SSH handlers")
    }

    func testSSHStartsOnlyAfterUpgradeAndWritesMaskedWebSocketFrame() throws {
        let channel = EmbeddedChannel()
        defer { _ = try? channel.finish() }
        let upgrade = UpgradeState()
        let ready = channel.eventLoop.makePromise(of: Void.self)
        upgrade.install(ready)
        try CloudflareSSHConnector.configureUpgrade(channel: channel, host: "relay.invalid",
            path: "/v1/ssh/nixos", token: "fixture", upgrade: upgrade).wait()

        var sshStart: Result<Void, Error>?
        ready.futureResult.whenComplete { result in
            sshStart = result.flatMap {
                Result {
                    let configuration = SSHClientConfiguration(userAuthDelegate: NoAuthentication(),
                                                               serverAuthDelegate: NoHostKeyValidation())
                    try channel.pipeline.syncOperations.addHandler(NIOSSHHandler(role: .client(configuration),
                        allocator: channel.allocator, inboundChildChannelInitializer: nil))
                }
            }
        }
        try channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 443)).wait()
        var request = ""
        while var part = try channel.readOutbound(as: ByteBuffer.self) {
            request += part.readString(length: part.readableBytes) ?? ""
        }
        let keyLine = try XCTUnwrap(request.components(separatedBy: "\r\n").first {
            $0.lowercased().hasPrefix("sec-websocket-key:")
        })
        let key = keyLine.split(separator: ":", maxSplits: 1)[1].trimmingCharacters(in: .whitespaces)
        let acceptInput = Data((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").utf8)
        let accept = Data(Insecure.SHA1.hash(data: acceptInput)).base64EncodedString()
        let response = "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: \(accept)\r\nSec-WebSocket-Protocol: nexus-ssh-v1\r\n\r\n"
        // The server may send its SSH greeting in the same read as the 101 response.
        // It must survive until Citadel's SSH handler has been installed.
        let serverGreeting = "SSH-2.0-fixture\r\n"
        var incoming = channel.allocator.buffer(string: response)
        incoming.writeInteger(UInt8(0x82))
        incoming.writeInteger(UInt8(serverGreeting.utf8.count))
        incoming.writeString(serverGreeting)
        try channel.writeInbound(incoming)
        channel.embeddedEventLoop.run()
        try XCTUnwrap(sshStart).get()

        var wire: [UInt8] = []
        while var part = try channel.readOutbound(as: ByteBuffer.self) {
            wire += part.readBytes(length: part.readableBytes) ?? []
        }
        XCTAssertGreaterThanOrEqual(wire.count, 6)
        guard wire.count >= 6 else { return }
        XCTAssertEqual(wire[0], 0x82, "SSH bytes must be sent as a binary frame")
        XCTAssertEqual(wire[1] & 0x80, 0x80, "Client frames must be masked")
        let length = Int(wire[1] & 0x7f)
        XCTAssertLessThan(length, 126)
        guard length < 126, wire.count >= 6 + length else { return XCTFail("Incomplete SSH frame") }
        let keyBytes = Array(wire[2..<6])
        let payload = wire[6..<(6 + length)].enumerated().map { $0.element ^ keyBytes[$0.offset % 4] }
        XCTAssertTrue(String(decoding: payload, as: UTF8.self).hasPrefix("SSH-2.0-"))
        XCTAssertGreaterThan(wire.count, 6 + length, "The server greeting must reach SSH and trigger key exchange")
    }
}

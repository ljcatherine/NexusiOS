import Foundation
import Citadel
import NIO
import NIOHTTP1
import NIOWebSocket
import NIOSSL

/// Opens an SSH byte stream over an HTTPS WebSocket. The Cloudflare Access bearer is
/// used only for the outer request; it is never sent to the upstream SSH host.
public enum CloudflareSSHConnector {
    public static func connect(settings: SSHClientSettings, target: String, accessToken: String) async throws -> SSHClient {
        guard settings.port == 443, ["nixos", "debian"].contains(target),
              !accessToken.isEmpty, accessToken.utf8.count <= 16_384 else {
            throw SSHFailure.cloudflareRelayUnavailable
        }
        let tls = TLSConfiguration.makeClientConfiguration()
        var configuration = tls
        configuration.certificateVerification = .fullVerification
        configuration.applicationProtocols = ["http/1.1"]
        let sslContext = try NIOSSLContext(configuration: configuration)
        let upgrade = UpgradeState()

        let bootstrap = ClientBootstrap(group: settings.group)
            .connectTimeout(settings.connectTimeout)
            .channelInitializer { channel in
                let promise = channel.eventLoop.makePromise(of: Void.self)
                upgrade.install(promise)
                let sslHandler: NIOSSLClientHandler
                do { sslHandler = try NIOSSLClientHandler(context: sslContext, serverHostname: settings.host) }
                catch { return channel.eventLoop.makeFailedFuture(error) }
                return channel.pipeline.addHandler(sslHandler).flatMap {
                    configureUpgrade(channel: channel, host: settings.host,
                                     path: "/v1/ssh/\(target)", token: accessToken, upgrade: upgrade)
                }
            }

        let channel = try await bootstrap.connect(host: settings.host, port: settings.port).get()
        do {
            guard let upgraded = upgrade.future else { throw SSHFailure.cloudflareRelayUnavailable }
            let timeout = channel.eventLoop.scheduleTask(in: settings.connectTimeout) {
                upgrade.fail(SSHFailure.connectionTimedOut)
            }
            defer { timeout.cancel() }
            try await upgraded.get()
            return try await SSHClient.connect(on: channel, settings: settings)
        } catch {
            channel.close(promise: nil)
            throw error
        }
    }

    static func configureUpgrade(channel: Channel, host: String, path: String, token: String,
                                 upgrade: UpgradeState) -> EventLoopFuture<Void> {
        let requestHandler = SSHWebSocketUpgradeRequestHandler(host: host, path: path, token: token, upgrade: upgrade)
        let upgrader = NIOWebSocketClientUpgrader(maxFrameSize: 1 << 20) { channel, response in
            guard response.status == .switchingProtocols,
                  response.headers["Sec-WebSocket-Protocol"].first == "nexus-ssh-v1" else {
                let error = SSHFailure.cloudflareRelayUnavailable
                upgrade.fail(error)
                return channel.eventLoop.makeFailedFuture(error)
            }
            let installed = channel.pipeline.addHandler(SSHWebSocketByteStreamHandler(), position: .last).flatMap {
                channel.pipeline.removeHandler(requestHandler)
            }
            installed.whenComplete { result in
                // Let NIO finish its upgrade callback and remove the HTTP upgrader before
                // a waiting SSH client can add handlers and immediately write bytes.
                channel.eventLoop.execute {
                    switch result {
                    case .success: upgrade.succeed()
                    case .failure(let error): upgrade.fail(error)
                    }
                }
            }
            return installed
        }
        // NIO invokes this callback before upgrader.upgrade installs WebSocket handlers.
        let configuration: NIOHTTPClientUpgradeSendableConfiguration = (upgraders: [upgrader], completionHandler: { _ in })
        return channel.pipeline.addHTTPClientHandlers(leftOverBytesStrategy: .forwardBytes,
                                                      withClientUpgrade: configuration).flatMap {
            channel.pipeline.addHandler(requestHandler)
        }
    }
}

final class UpgradeState: @unchecked Sendable {
    private let lock = NSLock()
    private var promise: EventLoopPromise<Void>?
    private var finished = false
    func install(_ value: EventLoopPromise<Void>) { lock.lock(); promise = value; lock.unlock() }
    var future: EventLoopFuture<Void>? { lock.lock(); defer { lock.unlock() }; return promise?.futureResult }
    func succeed() { complete(.success(())) }
    func fail(_ error: Error) { complete(.failure(error)) }
    private func complete(_ result: Result<Void, Error>) {
        lock.lock()
        guard !finished else { lock.unlock(); return }
        finished = true
        let current = promise
        lock.unlock()
        guard let current else { return }
        switch result {
        case .success: current.succeed(())
        case .failure(let error): current.fail(error)
        }
    }
}

private final class SSHWebSocketUpgradeRequestHandler: ChannelInboundHandler, RemovableChannelHandler, @unchecked Sendable {
    typealias InboundIn = HTTPClientResponsePart
    typealias OutboundOut = HTTPClientRequestPart

    private let host: String
    private let path: String
    private let token: String
    private let upgrade: UpgradeState

    init(host: String, path: String, token: String, upgrade: UpgradeState) {
        self.host = host; self.path = path; self.token = token; self.upgrade = upgrade
    }

    func channelActive(context: ChannelHandlerContext) {
        var head = HTTPRequestHead(version: .http1_1, method: .GET, uri: path)
        head.headers.add(name: "Host", value: host)
        head.headers.add(name: "Authorization", value: "Bearer \(token)")
        head.headers.add(name: "Sec-WebSocket-Protocol", value: "nexus-ssh-v1")
        context.write(wrapOutboundOut(.head(head)), promise: nil)
        context.writeAndFlush(wrapOutboundOut(.end(nil)), promise: nil)
        context.fireChannelActive()
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        if case .head(let response) = unwrapInboundIn(data), response.status != .switchingProtocols {
            upgrade.fail(SSHFailure.cloudflareRelayUnavailable)
        }
        context.fireChannelRead(data)
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        upgrade.fail(error)
        context.fireErrorCaught(error)
    }

    func channelInactive(context: ChannelHandlerContext) {
        upgrade.fail(SSHFailure.cloudflareRelayUnavailable)
        context.fireChannelInactive()
    }
}

/// Bridges the NIO WebSocket frame pipeline to Citadel's SSH byte stream. `Any` is deliberate:
/// SSH writes ByteBuffers while WebSocket control traffic writes frames through this same handler.
private final class SSHWebSocketByteStreamHandler: ChannelDuplexHandler, @unchecked Sendable {
    typealias InboundIn = Any
    typealias InboundOut = Any
    typealias OutboundIn = Any
    typealias OutboundOut = Any

    private var bufferingUntilSSHStarts = true
    private var drainScheduled = false
    private var pendingBytes = 0
    private var pendingBuffers: [ByteBuffer] = []
    private let maximumPendingBytes = 1 << 20

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        guard let frame = unwrapInboundIn(data) as? WebSocketFrame else {
            // Citadel's SSH handler expects bytes. An unexpected frame type must
            // never cross this boundary and trigger NIO's force-cast trap.
            context.fireErrorCaught(SSHFailure.cloudflareRelayUnavailable)
            context.close(promise: nil)
            return
        }
        switch frame.opcode {
        case .binary, .continuation:
            let bytes = frame.unmaskedData
            if bufferingUntilSSHStarts {
                guard pendingBuffers.count < 1024,
                      bytes.readableBytes <= maximumPendingBytes - pendingBytes else {
                    context.close(promise: nil)
                    return
                }
                pendingBytes += bytes.readableBytes
                pendingBuffers.append(bytes)
            } else {
                context.fireChannelRead(wrapInboundOut(bytes))
            }
        case .ping:
            context.writeAndFlush(wrapOutboundOut(
                WebSocketFrame(fin: true, opcode: .pong, maskKey: .random(), data: frame.unmaskedData)), promise: nil)
        case .connectionClose:
            context.close(promise: nil)
        case .pong, .text:
            break
        default:
            context.close(promise: nil)
        }
    }

    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        let outbound = unwrapOutboundIn(data)
        if let bytes = outbound as? ByteBuffer {
            schedulePendingDrain(context: context)
            context.write(wrapOutboundOut(WebSocketFrame(fin: true, opcode: .binary, maskKey: .random(), data: bytes)), promise: promise)
        } else if let ioData = outbound as? IOData, case .byteBuffer(let bytes) = ioData {
            schedulePendingDrain(context: context)
            context.write(wrapOutboundOut(WebSocketFrame(fin: true, opcode: .binary, maskKey: .random(), data: bytes)), promise: promise)
        } else if outbound is WebSocketFrame {
            // Preserve already-framed WebSocket control writes such as pong responses.
            context.write(data, promise: promise)
        } else {
            // WebSocketFrameEncoder force-casts its input; forwarding unknown
            // values (including non-byte IOData) can crash the process.
            promise?.fail(SSHFailure.cloudflareRelayUnavailable)
            context.close(promise: nil)
        }
    }

    private func schedulePendingDrain(context: ChannelHandlerContext) {
        guard bufferingUntilSSHStarts, !drainScheduled else { return }
        drainScheduled = true
        // SSH sends its identification from handlerAdded. Defer delivery until the
        // current pipeline mutation finishes, so the SSH handlers are all present.
        context.eventLoop.execute {
            self.bufferingUntilSSHStarts = false
            let buffers = self.pendingBuffers
            self.pendingBuffers.removeAll()
            self.pendingBytes = 0
            guard context.channel.isActive else { return }
            for bytes in buffers { context.fireChannelRead(self.wrapInboundOut(bytes)) }
            if !buffers.isEmpty { context.fireChannelReadComplete() }
        }
    }
}

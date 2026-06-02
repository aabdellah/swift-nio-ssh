//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2019 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Crypto
import NIOCore
import NIOEmbedded
import XCTest

@testable import NIOSSH

enum EndToEndTestError: Error {
    case unableToCreateChildChannel
}

class BackToBackEmbeddedChannel {
    private(set) var client: EmbeddedChannel
    private(set) var server: EmbeddedChannel
    private var loop: EmbeddedEventLoop

    private(set) var activeServerChannels: [Channel]

    var clientSSHHandler: NIOSSHHandler? {
        try? self.client.pipeline.syncOperations.handler(type: NIOSSHHandler.self)
    }

    var serverSSHHandler: NIOSSHHandler? {
        try? self.server.pipeline.syncOperations.handler(type: NIOSSHHandler.self)
    }

    init() {
        self.loop = EmbeddedEventLoop()
        self.client = EmbeddedChannel(loop: self.loop)
        self.server = EmbeddedChannel(loop: self.loop)
        self.activeServerChannels = []
    }

    func run() {
        self.loop.run()
    }

    func interactInMemory() throws {
        var workToDo = true

        while workToDo {
            workToDo = false

            self.loop.run()
            let clientDatum = try self.client.readOutbound(as: IOData.self)
            let serverDatum = try self.server.readOutbound(as: IOData.self)

            if let clientMsg = clientDatum {
                try self.server.writeInbound(clientMsg)
                workToDo = true
            }

            if let serverMsg = serverDatum {
                try self.client.writeInbound(serverMsg)
                workToDo = true
            }
        }
    }

    func advanceTime(by increment: TimeAmount) {
        self.loop.advanceTime(by: increment)
    }

    func activate() throws {
        // A weird wrinkle of embedded channel is that it only properly activates on connect.
        try self.client.connect(to: .init(unixDomainSocketPath: "/fake")).wait()
        try self.server.connect(to: .init(unixDomainSocketPath: "/fake")).wait()
    }

    func configureWithHarness(_ harness: TestHarness) throws {
        var clientConfig = SSHClientConfiguration(
            userAuthDelegate: harness.clientAuthDelegate,
            serverAuthDelegate: harness.clientServerAuthDelegate,
            globalRequestDelegate: harness.clientGlobalRequestDelegate
        )
        clientConfig.rekeyLimit = harness.clientRekeyLimit
        let clientHandler = NIOSSHHandler(
            role: .client(clientConfig),
            allocator: self.client.allocator,
            inboundChildChannelInitializer: nil
        )
        let serverHandler = NIOSSHHandler(
            role: .server(
                .init(
                    hostKeys: harness.serverHostKeys,
                    userAuthDelegate: harness.serverAuthDelegate,
                    globalRequestDelegate: harness.serverGlobalRequestDelegate,
                    banner: harness.serverAuthBanner
                )
            ),
            allocator: self.server.allocator
        ) { channel, _ in
            self.activeServerChannels.append(channel)
            let boxedSelf = NIOLoopBound(self, eventLoop: channel.eventLoop)
            channel.closeFuture.whenComplete { _ in
                boxedSelf.value.activeServerChannels.removeAll(where: { $0 === channel })
            }
            return channel.eventLoop.makeSucceededFuture(())
        }

        try self.client.pipeline.syncOperations.addHandler(clientHandler)
        try self.server.pipeline.syncOperations.addHandler(serverHandler)
    }

    func finish() throws {
        XCTAssertNoThrow(XCTAssertTrue(try self.client.finish(acceptAlreadyClosed: true).isClean))
        XCTAssertNoThrow(XCTAssertTrue(try self.server.finish(acceptAlreadyClosed: true).isClean))
        XCTAssertNoThrow(try self.loop.syncShutdownGracefully())
    }

    func createNewChannel() throws -> Channel {
        var clientChannel = Optional<Channel>.none
        self.clientSSHHandler?.createChannel { channel, _ in
            clientChannel = channel
            return channel.eventLoop.makeSucceededFuture(())
        }

        guard let channel = clientChannel else {
            XCTFail("Unable to create child channel")
            throw EndToEndTestError.unableToCreateChildChannel
        }

        return channel
    }
}

/// A straightforward test harness.
struct TestHarness {
    var clientAuthDelegate: NIOSSHClientUserAuthenticationDelegate = InfinitePasswordDelegate()

    var clientServerAuthDelegate: NIOSSHClientServerAuthenticationDelegate = AcceptAllHostKeysDelegate()

    var clientGlobalRequestDelegate: GlobalRequestDelegate?

    var serverAuthDelegate: NIOSSHServerUserAuthenticationDelegate = DenyThenAcceptDelegate(messagesToDeny: 0)

    var serverGlobalRequestDelegate: GlobalRequestDelegate?

    var serverHostKeys: [NIOSSHPrivateKey] = [.init(ed25519Key: .init())]

    var serverAuthBanner: SSHServerConfiguration.UserAuthBanner?

    var clientRekeyLimit: SSHClientConfiguration.RekeyLimit?
}

final class UserEventExpecter: ChannelInboundHandler {
    typealias InboundIn = Any

    var userEvents: [Any] = []

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        self.userEvents.append(event)
        context.fireUserInboundEventTriggered(event)
    }
}

/// Accumulates the plaintext payload of every `.channel`-type `SSHChannelData` read on
/// a child channel, in order. Used by the cross-rekey data-flow test to prove all bytes
/// arrive intact across a mid-stream rekey.
final class ChannelDataAccumulator: ChannelInboundHandler {
    typealias InboundIn = SSHChannelData
    typealias InboundOut = SSHChannelData

    private(set) var received = ByteBuffer()

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let channelData = self.unwrapInboundIn(data)
        if case .channel = channelData.type, case .byteBuffer(var buffer) = channelData.data {
            self.received.writeBuffer(&buffer)
        }
        context.fireChannelRead(data)
    }
}

final class PrivateKeyClientAuth: NIOSSHClientUserAuthenticationDelegate {
    private var key: NIOSSHPrivateKey?

    init(_ key: NIOSSHPrivateKey) {
        self.key = key
    }

    func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    ) {
        guard availableMethods.contains(.publicKey), let key = self.key else {
            nextChallengePromise.succeed(nil)
            return
        }

        self.key = nil
        nextChallengePromise.succeed(
            .init(username: "foo", serviceName: "ssh-connection", offer: .privateKey(.init(privateKey: key)))
        )
    }
}

final class ExpectPublicKeyAuth: NIOSSHServerUserAuthenticationDelegate {
    private var key: NIOSSHPublicKey

    init(_ key: NIOSSHPublicKey) {
        self.key = key
    }

    let supportedAuthenticationMethods: NIOSSHAvailableUserAuthenticationMethods = .publicKey

    func requestReceived(
        request: NIOSSHUserAuthenticationRequest,
        responsePromise: EventLoopPromise<NIOSSHUserAuthenticationOutcome>
    ) {
        guard case .publicKey(let actualKey) = request.request else {
            responsePromise.succeed(.failure)
            return
        }

        if actualKey.publicKey == self.key {
            responsePromise.succeed(.success)
        } else {
            responsePromise.succeed(.failure)
        }
    }
}

class EndToEndTests: XCTestCase {
    var channel: BackToBackEmbeddedChannel!

    override func setUp() {
        self.channel = BackToBackEmbeddedChannel()
    }

    override func tearDown() {
        try? self.channel.finish()
        self.channel = nil
    }

    /// This test validates that all the channel requests round-trip appropriately.
    func testChannelRequests() throws {
        XCTAssertNoThrow(try self.channel.configureWithHarness(TestHarness()))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // Create a channel.
        let clientChannel = try self.channel.createNewChannel()
        XCTAssertNoThrow(try self.channel.interactInMemory())
        guard let serverChannel = self.channel.activeServerChannels.first else {
            XCTFail("Server channel not created")
            return
        }

        let userEventRecorder = UserEventExpecter()
        XCTAssertNoThrow(try serverChannel.pipeline.syncOperations.addHandler(userEventRecorder))

        func helper<Event: Equatable>(_ event: Event) {
            let clientSent = NIOLoopBoundBox(false, eventLoop: clientChannel.eventLoop)

            let promise = clientChannel.eventLoop.makePromise(of: Void.self)
            clientChannel.pipeline.syncOperations.triggerUserOutboundEvent(event, promise: promise)
            promise.futureResult.whenSuccess { clientSent.value = true }
            XCTAssertNoThrow(try self.channel.interactInMemory())

            XCTAssertTrue(clientSent.value)
            XCTAssertEqual(userEventRecorder.userEvents.last as? Event?, event)
        }

        helper(SSHChannelRequestEvent.ExecRequest(command: "uname -a", wantReply: true))
        helper(SSHChannelRequestEvent.EnvironmentRequest(wantReply: true, name: "foo", value: "bar"))
        helper(SSHChannelRequestEvent.ExitStatus(exitStatus: 5))
        helper(
            SSHChannelRequestEvent.PseudoTerminalRequest(
                wantReply: true,
                term: "vt100",
                terminalCharacterWidth: 80,
                terminalRowHeight: 24,
                terminalPixelWidth: 0,
                terminalPixelHeight: 0,
                terminalModes: .init([.ECHO: 5])
            )
        )
        helper(SSHChannelRequestEvent.ShellRequest(wantReply: true))
        helper(
            SSHChannelRequestEvent.ExitSignal(
                signalName: "ILL",
                errorMessage: "illegal instruction",
                language: "en",
                dumpedCore: true
            )
        )
        helper(SSHChannelRequestEvent.SubsystemRequest(subsystem: "file transfer", wantReply: false))
        helper(
            SSHChannelRequestEvent.WindowChangeRequest(
                terminalCharacterWidth: 0,
                terminalRowHeight: 0,
                terminalPixelWidth: 720,
                terminalPixelHeight: 480
            )
        )
        helper(SSHChannelRequestEvent.LocalFlowControlRequest(clientCanDo: true))
        helper(SSHChannelRequestEvent.SignalRequest(signal: "USR1"))
        helper(SSHChannelRequestEvent.BreakRequest(breakLength: 1000, wantReply: false))
        helper(ChannelSuccessEvent())
        helper(ChannelFailureEvent())
    }

    func testGlobalRequestWithDefaultDelegate() throws {
        XCTAssertNoThrow(try self.channel.configureWithHarness(TestHarness()))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        func helper(_ request: GlobalRequest.TCPForwardingRequest) throws -> GlobalRequest.TCPForwardingResponse? {
            let promise = self.channel.client.eventLoop.makePromise(of: GlobalRequest.TCPForwardingResponse?.self)
            self.channel.clientSSHHandler?.sendTCPForwardingRequest(request, promise: promise)
            try self.channel.interactInMemory()
            return try promise.futureResult.wait()
        }

        // The default delegate rejects everything.
        XCTAssertThrowsError(try helper(.listen(host: "localhost", port: 8765))) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .globalRequestRefused)
        }
        XCTAssertThrowsError(try helper(.cancel(host: "localhost", port: 8765))) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .globalRequestRefused)
        }
    }

    func testGlobalRequestWithCustomDelegate() throws {
        class CustomGlobalRequestDelegate: GlobalRequestDelegate {
            var requests: [GlobalRequest.TCPForwardingRequest] = []

            var port: Int? = 0

            func tcpForwardingRequest(
                _ request: GlobalRequest.TCPForwardingRequest,
                handler: NIOSSHHandler,
                promise: EventLoopPromise<GlobalRequest.TCPForwardingResponse>
            ) {
                self.requests.append(request)
                let port = self.port
                self.port = nil
                promise.succeed(.init(boundPort: port))
            }
        }

        let customDelegate = CustomGlobalRequestDelegate()
        var harness = TestHarness()
        harness.serverGlobalRequestDelegate = customDelegate

        XCTAssertNoThrow(try self.channel.configureWithHarness(harness))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        func helper(_ request: GlobalRequest.TCPForwardingRequest) throws -> GlobalRequest.TCPForwardingResponse? {
            let promise = self.channel.client.eventLoop.makePromise(of: GlobalRequest.TCPForwardingResponse?.self)
            self.channel.clientSSHHandler?.sendTCPForwardingRequest(request, promise: promise)
            try self.channel.interactInMemory()
            return try promise.futureResult.wait()
        }

        // This delegate accepts things.
        let firstResponse = try helper(.listen(host: "localhost", port: 8765))
        let secondResponse = try helper(.cancel(host: "localhost", port: 8765))

        XCTAssertEqual(firstResponse, GlobalRequest.TCPForwardingResponse(boundPort: 0))
        XCTAssertEqual(secondResponse, GlobalRequest.TCPForwardingResponse(boundPort: nil))

        XCTAssertEqual(
            customDelegate.requests,
            [.listen(host: "localhost", port: 8765), .cancel(host: "localhost", port: 8765)]
        )
    }

    func testUnknownGlobalRequestCanTriggerResponse() throws {
        // This test verifies that, when the boolean `wantReply` is true, an error reply is sent back

        XCTAssertNoThrow(try self.channel.configureWithHarness(TestHarness()))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // Force unwrap is used, because this is a test and the handler must exist
        let clientSSHHandler = self.channel.clientSSHHandler!

        // The arbitrary number of 12 has no meaning here
        // What _is_ important is that the amount of added bytes is greater than 0
        var randomPayload = self.channel.client.allocator.buffer(capacity: 12)
        randomPayload.writeBytes(Array(randomBytes: 12))

        let firstReply = self.channel.client.eventLoop.makePromise(of: ByteBuffer?.self)
        clientSSHHandler.sendGlobalRequestMessage(
            .init(wantReply: true, type: .unknown("test", randomPayload)),
            promise: firstReply
        )

        XCTAssertNoThrow(try self.channel.interactInMemory())
        XCTAssertThrowsError(try firstReply.futureResult.wait())

        let secondReply = self.channel.client.eventLoop.makePromise(of: ByteBuffer?.self)
        clientSSHHandler.sendGlobalRequestMessage(
            .init(wantReply: false, type: .unknown("test", randomPayload)),
            promise: secondReply
        )

        XCTAssertNoThrow(try self.channel.interactInMemory())
        XCTAssertNil(try secondReply.futureResult.wait())
    }

    func testInboundUnknownGlobalRequestReachesDelegate() throws {
        // An inbound unknown global request (e.g. `hostkeys-00@openssh.com`, which uses
        // wantReply == false) must be delivered to the client's global request delegate with its
        // name and payload intact, and must NOT produce a REQUEST_FAILURE on the wire.
        final class CapturingDelegate: GlobalRequestDelegate {
            var captured: [(name: String, data: [UInt8], wantReply: Bool)] = []

            func unknownGlobalRequest(
                _ name: String,
                data: ByteBuffer,
                handler: NIOSSHHandler,
                wantReply: Bool,
                promise: EventLoopPromise<ByteBuffer?>?
            ) {
                self.captured.append((name: name, data: Array(data.readableBytesView), wantReply: wantReply))
                // wantReply == false here: promise is nil. Nothing to fulfil.
                promise?.succeed(nil)
            }
        }

        let delegate = CapturingDelegate()
        var harness = TestHarness()
        harness.clientGlobalRequestDelegate = delegate

        XCTAssertNoThrow(try self.channel.configureWithHarness(harness))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // The server sends an unknown, no-reply global request to the client.
        let serverSSHHandler = self.channel.serverSSHHandler!
        var payload = self.channel.server.allocator.buffer(capacity: 4)
        payload.writeBytes([0xDE, 0xAD, 0xBE, 0xEF])

        serverSSHHandler.sendGlobalRequestMessage(
            .init(wantReply: false, type: .unknown("hostkeys-00@openssh.com", payload)),
            promise: nil
        )

        XCTAssertNoThrow(try self.channel.interactInMemory())

        // The delegate observed the request, name + payload intact, wantReply == false.
        XCTAssertEqual(delegate.captured.count, 1)
        XCTAssertEqual(delegate.captured.first?.name, "hostkeys-00@openssh.com")
        XCTAssertEqual(delegate.captured.first?.data, [0xDE, 0xAD, 0xBE, 0xEF])
        XCTAssertEqual(delegate.captured.first?.wantReply, false)

        // No REQUEST_FAILURE may have been sent back: if the client had spuriously replied, the
        // server would have no pending response promise and would error, tripping the clean-finish
        // assertion in tearDown. Confirm there is no further outbound traffic from the client.
        XCTAssertNil(try self.channel.client.readOutbound(as: IOData.self))
    }

    func testInboundUnknownGlobalRequestWithReplyRoundTrips() throws {
        // When wantReply == true, a delegate that succeeds the promise with a buffer must produce a
        // REQUEST_SUCCESS reply carrying that buffer back to the requester.
        final class ReplyingDelegate: GlobalRequestDelegate {
            var capturedName: String?

            func unknownGlobalRequest(
                _ name: String,
                data: ByteBuffer,
                handler: NIOSSHHandler,
                wantReply: Bool,
                promise: EventLoopPromise<ByteBuffer?>?
            ) {
                self.capturedName = name
                var reply = handler.channel?.allocator.buffer(capacity: 3) ?? ByteBufferAllocator().buffer(capacity: 3)
                reply.writeBytes([0x01, 0x02, 0x03])
                promise?.succeed(reply)
            }
        }

        let delegate = ReplyingDelegate()
        var harness = TestHarness()
        harness.serverGlobalRequestDelegate = delegate

        XCTAssertNoThrow(try self.channel.configureWithHarness(harness))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        let clientSSHHandler = self.channel.clientSSHHandler!
        var payload = self.channel.client.allocator.buffer(capacity: 2)
        payload.writeBytes([0xAA, 0xBB])

        let reply = self.channel.client.eventLoop.makePromise(of: ByteBuffer?.self)
        clientSSHHandler.sendGlobalRequestMessage(
            .init(wantReply: true, type: .unknown("hostkeys-prove-00@openssh.com", payload)),
            promise: reply
        )

        XCTAssertNoThrow(try self.channel.interactInMemory())

        XCTAssertEqual(delegate.capturedName, "hostkeys-prove-00@openssh.com")
        let replyBuffer = try reply.futureResult.wait()
        XCTAssertEqual(replyBuffer.map { Array($0.readableBytesView) }, [0x01, 0x02, 0x03])
    }

    func testGlobalRequestTooEarlyIsDelayed() throws {
        let completed = NIOLoopBoundBox(false, eventLoop: self.channel.client.eventLoop)
        let promise = self.channel.client.eventLoop.makePromise(of: GlobalRequest.TCPForwardingResponse?.self)
        promise.futureResult.whenComplete { _ in completed.value = true }

        XCTAssertNoThrow(try self.channel.configureWithHarness(TestHarness()))

        // Issue a forwarding request early. This should be queued.
        self.channel.clientSSHHandler?.sendTCPForwardingRequest(
            .listen(host: "localhost", port: 2222),
            promise: promise
        )
        XCTAssertFalse(completed.value)

        // Activate. This will complete the forwarding request.
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        XCTAssertTrue(completed.value)
    }

    func testGlobalRequestsAreCancelledIfRemoved() throws {
        XCTAssertNoThrow(try self.channel.configureWithHarness(TestHarness()))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // Enqueue a global request.
        let err = NIOLoopBoundBox<Error?>(nil, eventLoop: self.channel.client.eventLoop)
        let promise = self.channel.client.eventLoop.makePromise(of: GlobalRequest.TCPForwardingResponse?.self)
        promise.futureResult.whenFailure { error in err.value = error }
        self.channel.clientSSHHandler?.sendTCPForwardingRequest(
            .listen(host: "localhost", port: 1234),
            promise: promise
        )
        XCTAssertNil(err.value)

        self.channel.client.close(promise: nil)
        XCTAssertNoThrow(try self.channel.interactInMemory())
        XCTAssertEqual(err.value as? ChannelError, .eof)
    }

    func testNeverStartedGlobalRequestsAreCancelledIfRemoved() throws {
        let err = NIOLoopBoundBox<Error?>(nil, eventLoop: self.channel.client.eventLoop)
        let promise = self.channel.client.eventLoop.makePromise(of: GlobalRequest.TCPForwardingResponse?.self)
        promise.futureResult.whenFailure { error in err.value = error }

        XCTAssertNoThrow(try self.channel.configureWithHarness(TestHarness()))

        // Enqueue a forwarding request
        self.channel.clientSSHHandler?.sendTCPForwardingRequest(
            .listen(host: "localhost", port: 1234),
            promise: promise
        )
        XCTAssertNil(err.value)

        // Now close the channel.
        self.channel.client.close(promise: nil)
        XCTAssertNoThrow(try self.channel.interactInMemory())
        XCTAssertEqual(err.value as? ChannelError, .eof)
    }

    func testGlobalRequestAfterCloseFails() throws {
        XCTAssertNoThrow(try self.channel.configureWithHarness(TestHarness()))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // Get an early ref to the handler.
        let handler = self.channel.clientSSHHandler

        // Close.
        self.channel.client.close(promise: nil)
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // Enqueue a global request.
        let err = NIOLoopBoundBox<Error?>(nil, eventLoop: self.channel.client.eventLoop)
        let promise = self.channel.client.eventLoop.makePromise(of: GlobalRequest.TCPForwardingResponse?.self)
        promise.futureResult.whenFailure { error in err.value = error }
        handler?.sendTCPForwardingRequest(.listen(host: "localhost", port: 1234), promise: promise)
        XCTAssertEqual(err.value as? ChannelError, .ioOnClosedChannel)
    }

    func testSecureEnclaveKeys() throws {
        // This is a quick end-to-end test that validates that we support secure enclave private keys
        // on appropriate platforms.
        #if canImport(Darwin)
        // If we can't create this key, we skip the test.
        let key: NIOSSHPrivateKey
        do {
            key = try .init(secureEnclaveP256Key: .init())
        } catch {
            return
        }

        // We use the Secure Enclave keys for everything, just because we can.
        var harness = TestHarness()
        harness.serverHostKeys = [key]
        harness.clientAuthDelegate = PrivateKeyClientAuth(key)
        harness.serverAuthDelegate = ExpectPublicKeyAuth(key.publicKey)

        XCTAssertNoThrow(try self.channel.configureWithHarness(harness))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // Create a channel, again, just because we can.
        _ = try self.channel.createNewChannel()
        XCTAssertNoThrow(try self.channel.interactInMemory())
        XCTAssertEqual(self.channel.activeServerChannels.count, 1)
        #endif
    }

    func testSupportClientInitiatedRekeying() throws {
        XCTAssertNoThrow(try self.channel.configureWithHarness(TestHarness()))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // Initiate re-keying on the client.
        XCTAssertNoThrow(try self.channel.clientSSHHandler!._rekey())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // We should be able to send a message here.
        XCTAssertEqual(self.channel.activeServerChannels.count, 0)
        self.channel.clientSSHHandler?.createChannel(nil, nil)
        XCTAssertNoThrow(try self.channel.interactInMemory())
        XCTAssertEqual(self.channel.activeServerChannels.count, 1)
    }

    func testPublicRekeyInitiatesWhenActiveAndIsNoOpOtherwise() throws {
        XCTAssertNoThrow(try self.channel.configureWithHarness(TestHarness()))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        let handler = self.channel.clientSSHHandler!
        let baseline = handler.rekeyInitiationCount

        // The public rekey() on a settled-active connection initiates a rekey.
        handler.rekey()
        XCTAssertEqual(handler.rekeyInitiationCount, baseline + 1)
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // A handler that was never attached to a pipeline (no context) is a
        // safe no-op: it must not crash, must not initiate a rekey, and must
        // fail any supplied promise with ioOnClosedChannel.
        let unattached = NIOSSHHandler(
            role: .client(SSHClientConfiguration(
                userAuthDelegate: TestHarness().clientAuthDelegate,
                serverAuthDelegate: AcceptAllHostKeysDelegate()
            )),
            allocator: self.channel.client.allocator,
            inboundChildChannelInitializer: nil
        )
        let promise = self.channel.client.eventLoop.makePromise(of: Void.self)
        unattached.rekey(promise: promise)
        XCTAssertEqual(unattached.rekeyInitiationCount, 0)
        XCTAssertThrowsError(try promise.futureResult.wait()) { error in
            XCTAssertEqual(error as? ChannelError, .ioOnClosedChannel)
        }
    }

    func testPublicRekeyPromiseResolvesOnCompletionNotInitiation() throws {
        XCTAssertNoThrow(try self.channel.configureWithHarness(TestHarness()))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        let handler = self.channel.clientSSHHandler!
        let completed = NIOLoopBoundBox(false, eventLoop: self.channel.client.eventLoop)
        let promise = self.channel.client.eventLoop.makePromise(of: Void.self)
        promise.futureResult.whenSuccess { completed.value = true }

        handler.rekey(promise: promise)
        // Initiation only: the client has sent KEXINIT but the peer has not
        // yet responded, so channel data is still forbidden and the promise
        // must NOT be fulfilled.
        XCTAssertFalse(completed.value, "rekey promise must not resolve on initiation")

        // Drive the key exchange to completion; the promise resolves once the
        // connection is rekeyable again (RFC 4253 §7.1 window closed).
        XCTAssertNoThrow(try self.channel.interactInMemory())
        XCTAssertTrue(completed.value, "rekey promise resolves on completion")
    }

    func testManualRekeyPromiseFailsWhenHostKeyValidationFailsOnRekey() throws {
        enum TestError: Error { case rejectedOnRekey }
        final class FailOnRekeyDelegate: NIOSSHClientServerAuthenticationDelegate {
            var count = 0
            func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
                self.count += 1
                if self.count == 1 {
                    validationCompletePromise.succeed(())  // initial handshake: trust
                } else {
                    validationCompletePromise.fail(TestError.rejectedOnRekey)  // rekey: reject
                }
            }
        }

        let delegate = FailOnRekeyDelegate()
        var harness = TestHarness()
        harness.clientServerAuthDelegate = delegate
        XCTAssertNoThrow(try self.channel.configureWithHarness(harness))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())
        XCTAssertEqual(delegate.count, 1, "initial handshake validated the host key")

        let handler = self.channel.clientSSHHandler!
        let failed = NIOLoopBoundBox(false, eventLoop: self.channel.client.eventLoop)
        let promise = self.channel.client.eventLoop.makePromise(of: Void.self)
        promise.futureResult.whenFailure { _ in failed.value = true }

        // The rekey re-validates the host key, which now fails — the async KEX
        // future fails. The rekey promise must FAIL (not hang): the .failure
        // path unblocks pending rekey waiters rather than stranding them.
        handler.rekey(promise: promise)
        try? self.channel.interactInMemory()
        XCTAssertGreaterThan(delegate.count, 1, "rekey re-validated the host key")
        XCTAssertTrue(failed.value, "rekey promise must fail when host-key validation fails on rekey")
    }

    func testSupportServerInitiatedRekeying() throws {
        XCTAssertNoThrow(try self.channel.configureWithHarness(TestHarness()))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // Initiate re-keying on the server.
        XCTAssertNoThrow(try self.channel.serverSSHHandler!._rekey())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // We should be able to send a message here.
        XCTAssertEqual(self.channel.activeServerChannels.count, 0)
        self.channel.clientSSHHandler?.createChannel(nil, nil)
        XCTAssertNoThrow(try self.channel.interactInMemory())
        XCTAssertEqual(self.channel.activeServerChannels.count, 1)
    }

    func testDataThresholdTriggersRekey() throws {
        var harness = TestHarness()
        harness.clientRekeyLimit = .init(dataBytes: 16384, interval: nil)
        XCTAssertNoThrow(try self.channel.configureWithHarness(harness))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // Open a child channel.
        let clientChannel = try self.channel.createNewChannel()
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // Snapshot the rekey count after the handshake + channel-open settle, so the
        // assertion isolates the effect of the data push regardless of handshake volume.
        let baseline = self.channel.clientSSHHandler!.rekeyInitiationCount

        // Push more than dataBytes of channel data from the client.
        var payload = clientChannel.allocator.buffer(capacity: 65536)
        payload.writeBytes(Array(repeating: UInt8(0x61), count: 65536))
        clientChannel.writeAndFlush(SSHChannelData(type: .channel, data: .byteBuffer(payload)), promise: nil)
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // A rekey must have been initiated by the byte threshold.
        XCTAssertGreaterThan(self.channel.clientSSHHandler!.rekeyInitiationCount, baseline)

        // And the session still works: a second channel opens fine.
        XCTAssertEqual(self.channel.activeServerChannels.count, 1)
        self.channel.clientSSHHandler?.createChannel(nil, nil)
        XCTAssertNoThrow(try self.channel.interactInMemory())
        XCTAssertEqual(self.channel.activeServerChannels.count, 2)
    }

    func testTimeThresholdTriggersRekey() throws {
        var harness = TestHarness()
        harness.clientRekeyLimit = .init(dataBytes: nil, interval: .seconds(10))
        XCTAssertNoThrow(try self.channel.configureWithHarness(harness))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // The handshake I/O installs the time-task. No rekey yet.
        let baseline = self.channel.clientSSHHandler!.rekeyInitiationCount

        // Fire the timer deterministically.
        self.channel.advanceTime(by: .seconds(10))
        XCTAssertNoThrow(try self.channel.interactInMemory())

        XCTAssertGreaterThan(self.channel.clientSSHHandler!.rekeyInitiationCount, baseline)

        // Session still works after the time-triggered rekey.
        self.channel.clientSSHHandler?.createChannel(nil, nil)
        XCTAssertNoThrow(try self.channel.interactInMemory())
        XCTAssertEqual(self.channel.activeServerChannels.count, 1)
    }

    func testNilRekeyLimitNeverRekeys() throws {
        // Default harness => rekeyLimit nil.
        XCTAssertNoThrow(try self.channel.configureWithHarness(TestHarness()))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        let clientChannel = try self.channel.createNewChannel()
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // Push lots of data and advance the clock; nothing should rekey.
        var payload = clientChannel.allocator.buffer(capacity: 131072)
        payload.writeBytes(Array(repeating: UInt8(0x62), count: 131072))
        clientChannel.writeAndFlush(SSHChannelData(type: .channel, data: .byteBuffer(payload)), promise: nil)
        XCTAssertNoThrow(try self.channel.interactInMemory())
        self.channel.advanceTime(by: .hours(1))
        XCTAssertNoThrow(try self.channel.interactInMemory())

        XCTAssertEqual(self.channel.clientSSHHandler!.rekeyInitiationCount, 0)
    }

    func testRekeyTimerCancelledOnHandlerRemoved() throws {
        var harness = TestHarness()
        harness.clientRekeyLimit = .init(dataBytes: nil, interval: .seconds(10))
        XCTAssertNoThrow(try self.channel.configureWithHarness(harness))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // Close the client channel: channelInactive + handlerRemoved must cancel the
        // scheduled time-task.
        let handler = self.channel.clientSSHHandler!
        let baseline = handler.rekeyInitiationCount
        XCTAssertNoThrow(try self.channel.client.close().wait())

        // Advancing time must NOT fire the cancelled task (no rekey, no crash).
        self.channel.advanceTime(by: .seconds(10))
        self.channel.run()
        XCTAssertEqual(handler.rekeyInitiationCount, baseline)
    }

    func testChannelDataSurvivesDataThresholdRekey() throws {
        var harness = TestHarness()
        // Low threshold so a rekey fires mid-stream.
        harness.clientRekeyLimit = .init(dataBytes: 4096, interval: nil)
        XCTAssertNoThrow(try self.channel.configureWithHarness(harness))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // Open a child channel and wire a data accumulator onto the server side.
        let clientChannel = try self.channel.createNewChannel()
        XCTAssertNoThrow(try self.channel.interactInMemory())
        guard let serverChannel = self.channel.activeServerChannels.first else {
            XCTFail("Server channel not created")
            return
        }
        let accumulator = ChannelDataAccumulator()
        XCTAssertNoThrow(try serverChannel.pipeline.syncOperations.addHandler(accumulator))

        // Build a payload larger than dataBytes and stream it in chunks, interleaving
        // interactInMemory so a rekey is triggered MID-STREAM.
        let chunkSize = 1024
        let chunkCount = 64  // 64 KiB total, well past the 4 KiB threshold.
        var expected = ByteBuffer()
        let baseline = self.channel.clientSSHHandler!.rekeyInitiationCount

        for chunk in 0..<chunkCount {
            var buffer = clientChannel.allocator.buffer(capacity: chunkSize)
            // Distinct byte per chunk so ordering errors are visible.
            buffer.writeBytes(Array(repeating: UInt8(chunk & 0xFF), count: chunkSize))
            expected.writeBytes(buffer.readableBytesView)
            clientChannel.writeAndFlush(SSHChannelData(type: .channel, data: .byteBuffer(buffer)), promise: nil)
            XCTAssertNoThrow(try self.channel.interactInMemory())
        }

        // Drain anything still in flight.
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // (1) A rekey actually occurred mid-stream.
        XCTAssertGreaterThan(self.channel.clientSSHHandler!.rekeyInitiationCount, baseline)

        // (2) The connection did NOT disconnect: the child channel is still active.
        XCTAssertEqual(self.channel.activeServerChannels.count, 1)

        // (3) ALL written bytes were received intact and in order.
        XCTAssertEqual(accumulator.received.readableBytes, expected.readableBytes)
        XCTAssertEqual(accumulator.received, expected)
    }

    func testDelayedHostKeyValidation() throws {
        class DelayedValidationDelegate: NIOSSHClientServerAuthenticationDelegate {
            var validationCount = 0

            func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
                // Short delay here, but we'll be forced to wait.
                let eventLoopSelf = NIOLoopBoundBox(
                    self,
                    eventLoop: validationCompletePromise.futureResult.eventLoop
                )
                validationCompletePromise.futureResult.eventLoop.scheduleTask(in: .milliseconds(100)) {
                    eventLoopSelf.value.validationCount += 1
                    validationCompletePromise.succeed(())
                }
            }
        }

        let delegate = DelayedValidationDelegate()
        var harness = TestHarness()
        harness.clientServerAuthDelegate = delegate

        // Set up the connection, validate all is well.
        XCTAssertNoThrow(try self.channel.configureWithHarness(harness))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // This will not be active yet! Advance time and interact again.
        XCTAssertEqual(delegate.validationCount, 0)
        self.channel.advanceTime(by: .milliseconds(100))
        XCTAssertNoThrow(try self.channel.interactInMemory())
        XCTAssertEqual(delegate.validationCount, 1)

        // We should be able to send a message here.
        XCTAssertEqual(self.channel.activeServerChannels.count, 0)
        self.channel.clientSSHHandler?.createChannel(nil, nil)
        XCTAssertNoThrow(try self.channel.interactInMemory())
        XCTAssertEqual(self.channel.activeServerChannels.count, 1)
    }

    func testHostKeyRejection() throws {
        enum TestError: Error {
            case bang
        }

        struct RejectDelegate: NIOSSHClientServerAuthenticationDelegate {
            func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
                validationCompletePromise.fail(TestError.bang)
            }
        }

        let errorCatcher = ErrorLoggingHandler()
        var harness = TestHarness()
        harness.clientServerAuthDelegate = RejectDelegate()

        // Set up the connection, validate all is well.
        XCTAssertNoThrow(try self.channel.configureWithHarness(harness))
        XCTAssertNoThrow(try self.channel.client.pipeline.syncOperations.addHandler(errorCatcher))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertThrowsError(try self.channel.interactInMemory()) { error in
            XCTAssertEqual(error as? TestError, .bang)
        }

        XCTAssertEqual(errorCatcher.errors.count, 1)
        XCTAssertEqual(errorCatcher.errors.first as? TestError, .bang)
    }

    func testCreateChannelBeforeIncompleteHandshakeFails() throws {
        enum TestError: Error {
            case bang
        }

        struct RejectDelegate: NIOSSHClientServerAuthenticationDelegate {
            func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
                validationCompletePromise.fail(TestError.bang)
            }
        }

        var harness = TestHarness()
        harness.clientServerAuthDelegate = RejectDelegate()

        XCTAssertNoThrow(try self.channel.configureWithHarness(harness))
        XCTAssertNoThrow(try self.channel.client.pipeline.syncOperations.addHandler(ErrorClosingHandler()))

        // Get an early ref to the handler and try to create a child channel.
        let handler = self.channel.clientSSHHandler

        let err = NIOLoopBoundBox<Error?>(nil, eventLoop: self.channel.client.eventLoop)
        let promise = self.channel.client.eventLoop.makePromise(of: Channel.self)
        promise.futureResult.whenFailure { error in err.value = error }
        handler!.createChannel(promise, channelType: .session) { channel, _ in
            channel.eventLoop.makeSucceededFuture(())
        }
        XCTAssertNil(err.value)

        // Activation errors.
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertThrowsError(try self.channel.interactInMemory()) { error in
            XCTAssertEqual(error as? TestError, .bang)
        }
        self.channel.run()
        XCTAssertEqual(err.value as? ChannelError?, .eof)
    }

    func testCreateChannelAfterDisconnectFailsWithEventLoopTick() throws {
        XCTAssertNoThrow(try self.channel.configureWithHarness(TestHarness()))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // Initiate disconnection on the client.
        XCTAssertNoThrow(try self.channel.clientSSHHandler!._disconnect())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // Attempting to create a child channel should immediately fail.
        let err = NIOLoopBoundBox<Error?>(nil, eventLoop: self.channel.client.eventLoop)
        let promise = self.channel.client.eventLoop.makePromise(of: Channel.self)
        promise.futureResult.whenFailure { error in err.value = error }
        self.channel.clientSSHHandler!.createChannel(promise, channelType: .session) { channel, _ in
            channel.eventLoop.makeSucceededFuture(())
        }
        self.channel.run()

        XCTAssertNotNil(err.value)
        XCTAssertEqual((err.value as? NIOSSHError)?.type, .creatingChannelAfterClosure)
    }

    func testCreateChannelAfterDisconnectFailsWithoutEventLoopTick() throws {
        XCTAssertNoThrow(try self.channel.configureWithHarness(TestHarness()))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // Initiate disconnection on the client.
        XCTAssertNoThrow(try self.channel.clientSSHHandler!._disconnect())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        // Attempting to create a child channel should immediately fail.
        let err = NIOLoopBoundBox<Error?>(nil, eventLoop: self.channel.client.eventLoop)
        let promise = self.channel.client.eventLoop.makePromise(of: Channel.self)
        promise.futureResult.whenFailure { error in err.value = error }
        self.channel.clientSSHHandler!.createChannel(promise, channelType: .session) { channel, _ in
            channel.eventLoop.makeSucceededFuture(())
        }
        self.channel.run()

        XCTAssertNotNil(err.value)
        XCTAssertEqual((err.value as? NIOSSHError)?.type, .creatingChannelAfterClosure)
    }

    func testHandshakeSuccess() throws {
        class ClientHandshakeHandler: ChannelInboundHandler {
            typealias InboundIn = Any

            let promise: EventLoopPromise<Void>

            init(promise: EventLoopPromise<Void>) {
                self.promise = promise
            }

            func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
                if event is UserAuthSuccessEvent {
                    self.promise.succeed(())
                }
            }
        }

        let promise = self.channel.client.eventLoop.makePromise(of: Void.self)
        let handshaker = ClientHandshakeHandler(promise: promise)

        let harness = TestHarness()

        // Set up the connection, validate all is well.
        XCTAssertNoThrow(try self.channel.configureWithHarness(harness))
        XCTAssertNoThrow(try self.channel.client.pipeline.syncOperations.addHandler(handshaker))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        XCTAssertNoThrow(try promise.futureResult.wait())
    }

    func testServerDoesNotSendBanner() throws {
        class ClientHandshakeHandler: ChannelInboundHandler {
            typealias InboundIn = Any

            var promise: EventLoopPromise<Void>?

            init(promise: EventLoopPromise<Void>) {
                self.promise = promise
            }

            func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
                guard let promise = self.promise else { return }
                self.promise = nil

                if event is NIOUserAuthBannerEvent {
                    promise.fail(HandshakeFailure.missingBanner)
                } else if event is UserAuthSuccessEvent {
                    promise.succeed(())
                }
            }

            enum HandshakeFailure: Error {
                case missingBanner
            }
        }

        let promise = self.channel.client.eventLoop.makePromise(of: Void.self)
        let handshaker = ClientHandshakeHandler(promise: promise)

        var harness = TestHarness()
        harness.serverAuthBanner = nil

        // Set up the connection, validate all is well.
        XCTAssertNoThrow(try self.channel.configureWithHarness(harness))
        XCTAssertNoThrow(try self.channel.client.pipeline.syncOperations.addHandler(handshaker))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        XCTAssertNoThrow(try promise.futureResult.wait())
    }

    func testCorrectBannerReceived() throws {
        class ClientHandshakeHandler: ChannelInboundHandler {
            typealias InboundIn = Any

            static let expectedAuthBannerMessage = "This is a demo user auth banner."
            static let expectedAuthBannerLanguageTag = "en"

            var promise: EventLoopPromise<(String, String)>?

            init(promise: EventLoopPromise<(String, String)>) {
                self.promise = promise
            }

            func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
                guard let promise = self.promise else { return }
                self.promise = nil

                if let event = event as? NIOUserAuthBannerEvent {
                    promise.succeed((event.message, event.languageTag))
                } else if event is UserAuthSuccessEvent {
                    promise.fail(HandshakeFailure.missingBanner)
                }
            }

            enum HandshakeFailure: Error {
                case missingBanner
            }
        }

        let promise = self.channel.client.eventLoop.makePromise(of: (String, String).self)
        let handshaker = ClientHandshakeHandler(promise: promise)

        var harness = TestHarness()
        harness.serverAuthBanner = .init(
            message: ClientHandshakeHandler.expectedAuthBannerMessage,
            languageTag: ClientHandshakeHandler.expectedAuthBannerLanguageTag
        )

        // Set up the connection, validate all is well.
        XCTAssertNoThrow(try self.channel.configureWithHarness(harness))
        XCTAssertNoThrow(try self.channel.client.pipeline.syncOperations.addHandler(handshaker))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        var banner = ("", "")
        XCTAssertNoThrow(banner = try promise.futureResult.wait())
        XCTAssertEqual(banner.0, ClientHandshakeHandler.expectedAuthBannerMessage)
        XCTAssertEqual(banner.1, ClientHandshakeHandler.expectedAuthBannerLanguageTag)
    }

    func testHandshakeFailure() throws {
        class ClientHandshakeHandler: ChannelInboundHandler {
            typealias InboundIn = Any

            let promise: EventLoopPromise<Void>

            init(promise: EventLoopPromise<Void>) {
                self.promise = promise
            }

            func errorCaught(context: ChannelHandlerContext, error: Error) {
                self.promise.fail(error)
            }
        }

        enum TestError: Error {
            case bang
        }

        struct BadPasswordDelegate: NIOSSHClientUserAuthenticationDelegate {
            func nextAuthenticationType(
                availableMethods: NIOSSHAvailableUserAuthenticationMethods,
                nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
            ) {
                nextChallengePromise.fail(TestError.bang)
            }
        }

        var harness = TestHarness()
        harness.clientAuthDelegate = BadPasswordDelegate()

        let promise = self.channel.client.eventLoop.makePromise(of: Void.self)
        let handshaker = ClientHandshakeHandler(promise: promise)

        // Set up the connection, validate all is well.
        XCTAssertNoThrow(try self.channel.configureWithHarness(harness))
        XCTAssertNoThrow(try self.channel.client.pipeline.syncOperations.addHandler(handshaker))
        XCTAssertNoThrow(try self.channel.activate())
        XCTAssertNoThrow(try self.channel.interactInMemory())

        XCTAssertThrowsError(try promise.futureResult.wait()) { error in
            XCTAssertEqual(error as? TestError, TestError.bang)
        }
    }
}

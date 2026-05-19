//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2020 Apple Inc. and the SwiftNIO project authors
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

/// A client auth delegate that offers `keyboard-interactive` and answers every prompt by
/// echoing a fixed answer suffixed with the prompt index.
private final class KeyboardInteractiveDelegate: NIOSSHClientUserAuthenticationDelegate {
    let username: String
    let submethods: String
    /// If non-nil, the delegate returns exactly this many responses regardless of the prompt
    /// count (used to exercise the RFC 4256 ยง3.4 count-mismatch rejection).
    let forcedResponseCount: Int?
    /// If true, the delegate fails the response promise to signal "give up".
    let giveUp: Bool

    private(set) var challengeInvocations = 0

    init(
        username: String = "foo",
        submethods: String = "",
        forcedResponseCount: Int? = nil,
        giveUp: Bool = false
    ) {
        self.username = username
        self.submethods = submethods
        self.forcedResponseCount = forcedResponseCount
        self.giveUp = giveUp
    }

    func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    ) {
        // OpenSSH-style clients offer keyboard-interactive proactively. The initial offer is
        // solicited with `.all` (which deliberately excludes keyboard-interactive on the
        // server-advertisable set), so we must not gate on availableMethods here.
        nextChallengePromise.succeed(
            NIOSSHUserAuthenticationOffer(
                username: self.username,
                serviceName: "",
                offer: .keyboardInteractive(.init(submethods: self.submethods))
            )
        )
    }

    func respondToKeyboardInteractiveChallenge(
        name: String,
        instruction: String,
        prompts: [KeyboardInteractivePrompt],
        responsePromise: EventLoopPromise<[String]>
    ) {
        self.challengeInvocations += 1

        if self.giveUp {
            responsePromise.fail(NIOSSHKeyboardInteractiveUnsupportedError())
            return
        }

        let count = self.forcedResponseCount ?? prompts.count
        responsePromise.succeed((0..<count).map { "answer-\($0)" })
    }
}

final class KeyboardInteractiveTests: XCTestCase {
    var loop: EmbeddedEventLoop!
    var sessionID: ByteBuffer!

    override func setUp() {
        self.loop = EmbeddedEventLoop()
        var buffer = ByteBufferAllocator().buffer(capacity: 32)
        buffer.writeBytes(0..<32)
        self.sessionID = buffer
    }

    override func tearDown() {
        try! self.loop.syncShutdownGracefully()
        self.loop = nil
    }

    // MARK: - Wire serialization round-trips

    func testInfoRequestRoundTrips() throws {
        let message = SSHMessage.userAuthInfoRequest(
            .init(
                name: "Verification",
                instruction: "Type your one-time codes",
                languageTag: "",
                prompts: [
                    .init(prompt: "Password: ", echo: false),
                    .init(prompt: "Token: ", echo: true),
                ]
            )
        )

        var buffer = ByteBufferAllocator().buffer(capacity: 256)
        buffer.writeSSHMessage(message)
        let decoded = try buffer.readSSHMessage(clientExpectingKeyboardInteractiveInfoRequest: true)
        XCTAssertEqual(decoded, message)
        XCTAssertEqual(buffer.readableBytes, 0)
    }

    func testInfoRequestZeroPromptRoundTrips() throws {
        let message = SSHMessage.userAuthInfoRequest(
            .init(name: "n", instruction: "i", languageTag: "", prompts: [])
        )
        var buffer = ByteBufferAllocator().buffer(capacity: 64)
        buffer.writeSSHMessage(message)
        XCTAssertEqual(
            try buffer.readSSHMessage(clientExpectingKeyboardInteractiveInfoRequest: true),
            message
        )
    }

    func testInfoResponseRoundTrips() throws {
        let message = SSHMessage.userAuthInfoResponse(.init(responses: ["hunter2", "123456"]))
        var buffer = ByteBufferAllocator().buffer(capacity: 64)
        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)
        XCTAssertEqual(buffer.readableBytes, 0)
    }

    func testKeyboardInteractiveUserAuthRequestRoundTrips() throws {
        let message = SSHMessage.userAuthRequest(
            .init(username: "foo", service: "ssh-connection", method: .keyboardInteractive("pam"))
        )
        var buffer = ByteBufferAllocator().buffer(capacity: 64)
        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)
        XCTAssertEqual(buffer.readableBytes, 0)
    }

    // MARK: - #60 disambiguation

    func testByte60IsInfoRequestWhenExpectingKeyboardInteractive() throws {
        let infoRequest = SSHMessage.userAuthInfoRequest(
            .init(name: "", instruction: "", languageTag: "", prompts: [.init(prompt: "p", echo: false)])
        )
        var buffer = ByteBufferAllocator().buffer(capacity: 64)
        buffer.writeSSHMessage(infoRequest)

        // First byte must be 60.
        XCTAssertEqual(buffer.getInteger(at: buffer.readerIndex, as: UInt8.self), 60)

        let decoded = try buffer.readSSHMessage(clientExpectingKeyboardInteractiveInfoRequest: true)
        guard case .some(.userAuthInfoRequest) = decoded else {
            XCTFail("Expected INFO_REQUEST, got \(String(describing: decoded))")
            return
        }
    }

    func testByte60IsPKOKWhenNotExpectingKeyboardInteractive() throws {
        // SSH_MSG_USERAUTH_PK_OK is also message number 60. With the password/publickey path
        // in flight (flag == false) byte 60 MUST decode as PK_OK, not INFO_REQUEST.
        let key = NIOSSHPrivateKey(ed25519Key: .init()).publicKey
        let pkOK = SSHMessage.userAuthPKOK(.init(key: key))
        var buffer = ByteBufferAllocator().buffer(capacity: 128)
        buffer.writeSSHMessage(pkOK)

        XCTAssertEqual(buffer.getInteger(at: buffer.readerIndex, as: UInt8.self), 60)

        let decoded = try buffer.readSSHMessage(clientExpectingKeyboardInteractiveInfoRequest: false)
        guard case .some(.userAuthPKOK) = decoded else {
            XCTFail("Expected PK_OK, got \(String(describing: decoded))")
            return
        }

        // Default argument must also be the non-keyboard-interactive interpretation, so that
        // the overwhelming majority of call sites cannot accidentally corrupt password auth.
        var buffer2 = ByteBufferAllocator().buffer(capacity: 128)
        buffer2.writeSSHMessage(pkOK)
        guard case .some(.userAuthPKOK) = try buffer2.readSSHMessage() else {
            XCTFail("Default disambiguation must decode byte 60 as PK_OK")
            return
        }
    }

    /// The packet parser must mirror the in-flight method onto its disambiguation flag, so
    /// that a password attempt still sees PK_OK/CHANGEREQ and a keyboard-interactive attempt
    /// sees INFO_REQUEST. This is the security-critical guarantee.
    func testParserDisambiguatesByExpectationFlag() throws {
        var parser = SSHPacketParser(isServer: false, allocator: ByteBufferAllocator())

        // Feed the protocol version first (the parser starts in `.initialized`).
        var version = ByteBufferAllocator().buffer(capacity: 64)
        version.writeString("SSH-2.0-Test\r\n")
        parser.append(bytes: &version)
        XCTAssertEqual(try parser.nextPacket(), .version("SSH-2.0-Test"))

        func framedBytes(for message: SSHMessage) -> ByteBuffer {
            // Build a minimally-valid cleartext SSH frame: length, padding length, payload, padding.
            var payload = ByteBufferAllocator().buffer(capacity: 64)
            payload.writeSSHMessage(message)
            let payloadLen = payload.readableBytes
            // Pad to a multiple of 8 with a minimum of 4 padding bytes.
            var paddingLen = 8 - ((payloadLen + 5) % 8)
            if paddingLen < 4 { paddingLen += 8 }
            var frame = ByteBufferAllocator().buffer(capacity: payloadLen + paddingLen + 8)
            frame.writeInteger(UInt32(payloadLen + paddingLen + 1))
            frame.writeInteger(UInt8(paddingLen))
            frame.writeImmutableBuffer(payload)
            frame.writeBytes(Array(repeating: UInt8(0), count: paddingLen))
            return frame
        }

        // Keyboard-interactive in flight: byte 60 -> INFO_REQUEST.
        parser.clientExpectingKeyboardInteractiveInfoRequest = true
        var infoFrame = framedBytes(
            for: .userAuthInfoRequest(
                .init(name: "", instruction: "", languageTag: "", prompts: [.init(prompt: "p", echo: false)])
            )
        )
        parser.append(bytes: &infoFrame)
        guard case .some(.userAuthInfoRequest) = try parser.nextPacket() else {
            XCTFail("Parser should decode byte 60 as INFO_REQUEST while expecting it")
            return
        }

        // Password/publickey in flight: byte 60 -> PK_OK.
        parser.clientExpectingKeyboardInteractiveInfoRequest = false
        let key = NIOSSHPrivateKey(ed25519Key: .init()).publicKey
        var pkOKFrame = framedBytes(for: .userAuthPKOK(.init(key: key)))
        parser.append(bytes: &pkOKFrame)
        guard case .some(.userAuthPKOK) = try parser.nextPacket() else {
            XCTFail("Parser must decode byte 60 as PK_OK when not expecting INFO_REQUEST")
            return
        }
    }

    // MARK: - State machine flows

    private func clientStateMachineReadyForInfoRequest(
        delegate: KeyboardInteractiveDelegate
    ) throws -> UserAuthenticationStateMachine {
        var stateMachine = UserAuthenticationStateMachine(
            role: .client(.init(userAuthDelegate: delegate, serverAuthDelegate: AcceptAllHostKeysDelegate())),
            loop: self.loop,
            sessionID: self.sessionID
        )

        _ = stateMachine.beginAuthentication()
        stateMachine.sendServiceRequest(.init(service: "ssh-userauth"))

        // Service accept -> the delegate offers keyboard-interactive.
        let future = try XCTUnwrap(try stateMachine.receiveServiceAccept(.init(service: "ssh-userauth")))
        let box = NIOLoopBoundBox<SSHMessage.UserAuthRequestMessage?>(nil, eventLoop: future.eventLoop)
        future.whenSuccess { box.value = $0 }
        self.loop.run()

        let request = try XCTUnwrap(box.value)
        XCTAssertEqual(request.method, .keyboardInteractive(delegate.submethods))
        stateMachine.sendUserAuthRequest(request)
        XCTAssertTrue(stateMachine.clientInFlightMethodIsKeyboardInteractive)
        return stateMachine
    }

    private func feedInfoRequest(
        _ message: SSHMessage.UserAuthInfoRequestMessage,
        into stateMachine: inout UserAuthenticationStateMachine
    ) throws -> Result<SSHMessage.UserAuthInfoResponseMessage, Error>? {
        guard let future = try stateMachine.receiveUserAuthInfoRequest(message) else {
            return nil
        }
        let box = NIOLoopBoundBox<Result<SSHMessage.UserAuthInfoResponseMessage, Error>?>(
            nil,
            eventLoop: future.eventLoop
        )
        future.whenComplete { box.value = $0 }
        self.loop.run()
        return box.value
    }

    func testMultiRoundKeyboardInteractiveEndingInSuccess() throws {
        let delegate = KeyboardInteractiveDelegate()
        var stateMachine = try self.clientStateMachineReadyForInfoRequest(delegate: delegate)

        // Round 1: two prompts.
        let round1 = try self.feedInfoRequest(
            .init(
                name: "n1",
                instruction: "i1",
                languageTag: "",
                prompts: [.init(prompt: "User: ", echo: true), .init(prompt: "Pass: ", echo: false)]
            ),
            into: &stateMachine
        )
        XCTAssertEqual(try round1?.get(), .init(responses: ["answer-0", "answer-1"]))

        // Round 2: one prompt. The state machine owns the loop, so this is legal without
        // any intervening USERAUTH_FAILURE.
        let round2 = try self.feedInfoRequest(
            .init(name: "", instruction: "", languageTag: "", prompts: [.init(prompt: "OTP: ", echo: false)]),
            into: &stateMachine
        )
        XCTAssertEqual(try round2?.get(), .init(responses: ["answer-0"]))

        XCTAssertEqual(delegate.challengeInvocations, 2)

        // Finally the server accepts.
        XCTAssertNoThrow(try stateMachine.receiveUserAuthSuccess())
    }

    func testZeroPromptInfoRequestAnswersWithEmptyResponseWithoutDelegate() throws {
        let delegate = KeyboardInteractiveDelegate()
        var stateMachine = try self.clientStateMachineReadyForInfoRequest(delegate: delegate)

        let result = try self.feedInfoRequest(
            .init(name: "MOTD", instruction: "Welcome", languageTag: "", prompts: []),
            into: &stateMachine
        )
        XCTAssertEqual(try result?.get(), .init(responses: []))
        // RFC 4256 ยง3.3 / OpenSSH: no user interaction for a zero-prompt request.
        XCTAssertEqual(delegate.challengeInvocations, 0)

        // The exchange can still continue and succeed afterwards.
        XCTAssertNoThrow(try stateMachine.receiveUserAuthSuccess())
    }

    func testResponseCountMismatchIsRejected() throws {
        // Delegate returns 1 response for a 2-prompt request.
        let delegate = KeyboardInteractiveDelegate(forcedResponseCount: 1)
        var stateMachine = try self.clientStateMachineReadyForInfoRequest(delegate: delegate)

        let result = try self.feedInfoRequest(
            .init(
                name: "",
                instruction: "",
                languageTag: "",
                prompts: [.init(prompt: "a", echo: true), .init(prompt: "b", echo: false)]
            ),
            into: &stateMachine
        )
        switch result {
        case .failure(let error as NIOSSHError):
            // Protocol violation for the count mismatch.
            XCTAssertNotNil(error)
        default:
            XCTFail("Expected protocol violation for response/prompt count mismatch, got \(String(describing: result))")
        }
    }

    func testDelegateGiveUpFailsTheRound() throws {
        let delegate = KeyboardInteractiveDelegate(giveUp: true)
        var stateMachine = try self.clientStateMachineReadyForInfoRequest(delegate: delegate)

        let result = try self.feedInfoRequest(
            .init(name: "", instruction: "", languageTag: "", prompts: [.init(prompt: "p", echo: false)]),
            into: &stateMachine
        )
        switch result {
        case .failure(let error):
            XCTAssertTrue(error is NIOSSHKeyboardInteractiveUnsupportedError)
        default:
            XCTFail("Expected the give-up error to propagate, got \(String(describing: result))")
        }
    }

    func testDefaultDelegateImplementationFailsPromise() {
        // SimplePasswordDelegate does not implement keyboard-interactive; the protocol
        // extension default must fail the promise so existing conformers are unaffected.
        let delegate: NIOSSHClientUserAuthenticationDelegate = SimplePasswordDelegate(
            username: "u",
            password: "p"
        )
        let promise = self.loop.makePromise(of: [String].self)
        delegate.respondToKeyboardInteractiveChallenge(
            name: "",
            instruction: "",
            prompts: [],
            responsePromise: promise
        )
        let box = NIOLoopBoundBox<Error?>(nil, eventLoop: self.loop)
        promise.futureResult.whenFailure { box.value = $0 }
        self.loop.run()
        XCTAssertTrue(box.value is NIOSSHKeyboardInteractiveUnsupportedError)
    }

    func testInfoRequestOutsideKeyboardInteractiveAttemptIsRejected() throws {
        // A password attempt must never accept an INFO_REQUEST: the state machine guards on
        // the in-flight method even if the byte somehow decoded as one.
        let delegate = SimplePasswordDelegate(username: "foo", password: "bar")
        var stateMachine = UserAuthenticationStateMachine(
            role: .client(.init(userAuthDelegate: delegate, serverAuthDelegate: AcceptAllHostKeysDelegate())),
            loop: self.loop,
            sessionID: self.sessionID
        )
        _ = stateMachine.beginAuthentication()
        stateMachine.sendServiceRequest(.init(service: "ssh-userauth"))
        let future = try XCTUnwrap(try stateMachine.receiveServiceAccept(.init(service: "ssh-userauth")))
        let box = NIOLoopBoundBox<SSHMessage.UserAuthRequestMessage?>(nil, eventLoop: future.eventLoop)
        future.whenSuccess { box.value = $0 }
        self.loop.run()
        let request = try XCTUnwrap(box.value)
        XCTAssertEqual(request.method, .password("bar"))
        stateMachine.sendUserAuthRequest(request)
        XCTAssertFalse(stateMachine.clientInFlightMethodIsKeyboardInteractive)

        XCTAssertThrowsError(
            try stateMachine.receiveUserAuthInfoRequest(
                .init(name: "", instruction: "", languageTag: "", prompts: [])
            )
        )
    }
}

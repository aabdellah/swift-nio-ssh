//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2026 Apple Inc. and the SwiftNIO project authors
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
import XCTest

@testable import NIOSSH

@available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
final class MLKEMKeyExchangeTests: XCTestCase {
    private func keyExchangeAgreed(_ first: KeyExchangeResult, _ second: KeyExchangeResult) {
        XCTAssertEqual(first.sessionID, second.sessionID)
        XCTAssertEqual(first.keys.initialInboundIV, second.keys.initialOutboundIV)
        XCTAssertEqual(first.keys.initialOutboundIV, second.keys.initialInboundIV)
        XCTAssertEqual(first.keys.inboundEncryptionKey, second.keys.outboundEncryptionKey)
        XCTAssertEqual(first.keys.outboundEncryptionKey, second.keys.inboundEncryptionKey)
        XCTAssertEqual(first.keys.inboundMACKey, second.keys.outboundMACKey)
        XCTAssertEqual(first.keys.outboundMACKey, second.keys.inboundMACKey)
    }

    private func runHandshake(previousSessionIdentifier: ByteBuffer?) throws {
        var server = MLKEM768X25519KeyExchange(
            ourRole: .server([.init(ed25519Key: .init())]),
            previousSessionIdentifier: previousSessionIdentifier
        )
        var client = MLKEM768X25519KeyExchange(
            ourRole: .client,
            previousSessionIdentifier: previousSessionIdentifier
        )
        let serverHostKey = NIOSSHPrivateKey(ed25519Key: .init())

        var initialExchangeBytes = ByteBufferAllocator().buffer(capacity: 2048)
        let clientMessage = client.initiateKeyExchangeClientSide(allocator: ByteBufferAllocator())
        // C_INIT = ek(1184) ‖ x25519(32) = 1216 bytes.
        XCTAssertEqual(clientMessage.publicKey.readableBytes, 1216)

        let (serverKeys, serverResponse) = try assertNoThrowWithValue(
            try server.completeKeyExchangeServerSide(
                clientKeyExchangeMessage: clientMessage,
                serverHostKey: serverHostKey,
                initialExchangeBytes: &initialExchangeBytes,
                allocator: ByteBufferAllocator(),
                expectedKeySizes: AES128GCMOpenSSHTransportProtection.keySizes
            )
        )
        // S_REPLY = ct(1088) ‖ x25519(32) = 1120 bytes.
        XCTAssertEqual(serverResponse.publicKey.readableBytes, 1120)

        initialExchangeBytes.clear()
        let clientKeys = try assertNoThrowWithValue(
            try client.receiveServerKeyExchangePayload(
                serverKeyExchangeMessage: serverResponse,
                initialExchangeBytes: &initialExchangeBytes,
                allocator: ByteBufferAllocator(),
                expectedKeySizes: AES128GCMOpenSSHTransportProtection.keySizes
            )
        )
        self.keyExchangeAgreed(serverKeys, clientKeys)
    }

    func testAgreementNoPreviousSession() throws {
        try self.runHandshake(previousSessionIdentifier: nil)
    }

    func testAgreementWithPreviousSession() throws {
        var previous = ByteBufferAllocator().buffer(capacity: 64)
        previous.writeBytes(0..<32)
        try self.runHandshake(previousSessionIdentifier: previous)
    }

    func testServerRejectsWrongLengthCInit() throws {
        var server = MLKEM768X25519KeyExchange(
            ourRole: .server([.init(ed25519Key: .init())]),
            previousSessionIdentifier: nil
        )
        let serverHostKey = NIOSSHPrivateKey(ed25519Key: .init())
        var initialExchangeBytes = ByteBufferAllocator().buffer(capacity: 2048)
        var shortBuffer = ByteBufferAllocator().buffer(capacity: 1215)
        shortBuffer.writeBytes(Array(repeating: UInt8(0), count: 1215))
        let badMessage = SSHMessage.KeyExchangeECDHInitMessage(publicKey: shortBuffer)
        XCTAssertThrowsError(
            try server.completeKeyExchangeServerSide(
                clientKeyExchangeMessage: badMessage,
                serverHostKey: serverHostKey,
                initialExchangeBytes: &initialExchangeBytes,
                allocator: ByteBufferAllocator(),
                expectedKeySizes: AES128GCMOpenSSHTransportProtection.keySizes
            )
        ) { error in
            XCTAssertEqual((error as? NIOSSHError).map { $0.type }, .invalidKeySize)
        }
    }

    func testClientRejectsTamperedSignature() throws {
        var server = MLKEM768X25519KeyExchange(
            ourRole: .server([.init(ed25519Key: .init())]),
            previousSessionIdentifier: nil
        )
        var client = MLKEM768X25519KeyExchange(ourRole: .client, previousSessionIdentifier: nil)
        let serverHostKey = NIOSSHPrivateKey(ed25519Key: .init())
        var initialExchangeBytes = ByteBufferAllocator().buffer(capacity: 2048)
        let clientMessage = client.initiateKeyExchangeClientSide(allocator: ByteBufferAllocator())
        var (_, serverResponse) = try assertNoThrowWithValue(
            try server.completeKeyExchangeServerSide(
                clientKeyExchangeMessage: clientMessage,
                serverHostKey: serverHostKey,
                initialExchangeBytes: &initialExchangeBytes,
                allocator: ByteBufferAllocator(),
                expectedKeySizes: AES128GCMOpenSSHTransportProtection.keySizes
            )
        )
        initialExchangeBytes.clear()
        serverResponse.signature = try assertNoThrowWithValue(
            serverHostKey.sign(digest: SHA256.hash(data: [9, 9, 9, 9]))
        )
        XCTAssertThrowsError(
            try client.receiveServerKeyExchangePayload(
                serverKeyExchangeMessage: serverResponse,
                initialExchangeBytes: &initialExchangeBytes,
                allocator: ByteBufferAllocator(),
                expectedKeySizes: AES128GCMOpenSSHTransportProtection.keySizes
            )
        ) { error in
            XCTAssertEqual((error as? NIOSSHError).map { $0.type }, .invalidExchangeHashSignature)
        }
    }
}

/// Registration/negotiation assertions. NOT macOS-26-gated: must verify behavior below the floor too.
final class MLKEMRegistrationTests: XCTestCase {
    func testAdvertisedAtLowestPreferenceWhenAvailable() {
        let algs = SSHKeyExchangeStateMachine.supportedKeyExchangeAlgorithms
        // Classical curve25519 is always advertised.
        XCTAssertTrue(algs.contains("curve25519-sha256"))
        if #available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *) {
            // On PQ-capable platforms the hybrid is advertised, but LAST (lowest preference).
            XCTAssertEqual(algs.last, "mlkem768x25519-sha256@openssh.com")
            guard let c = algs.firstIndex(of: "curve25519-sha256"),
                let m = algs.firstIndex(of: "mlkem768x25519-sha256@openssh.com")
            else { return XCTFail("expected both curve25519 and mlkem768 present") }
            XCTAssertLessThan(c, m)
        } else {
            // Below the floor the hybrid is not offered at all.
            XCTAssertFalse(algs.contains("mlkem768x25519-sha256@openssh.com"))
        }
    }
}

/// Mirrors the helper in ECKeyExchangeTests for constructing roles.
extension SSHConnectionRole {
    fileprivate static func server(_ hostKeys: [NIOSSHPrivateKey]) -> SSHConnectionRole {
        .server(SSHServerConfiguration(hostKeys: hostKeys, userAuthDelegate: DenyAllServerAuthDelegate()))
    }

    fileprivate static var client: SSHConnectionRole {
        .client(
            SSHClientConfiguration(
                userAuthDelegate: ExplodingAuthDelegate(),
                serverAuthDelegate: AcceptAllHostKeysDelegate()
            )
        )
    }
}

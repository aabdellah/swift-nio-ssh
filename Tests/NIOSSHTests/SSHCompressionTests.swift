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
import XCTest
import NIOCore
@testable import NIOSSH

final class SSHCompressionTests: XCTestCase {
    // MARK: - Helpers

    /// Build a symmetric TestTransportProtection pair (what the serializer sends,
    /// the parser can decrypt — same keys used for both directions so the test is
    /// self-contained without a real key exchange).
    @available(iOS 13.2, macOS 10.15, watchOS 6.1, tvOS 13.2, *)
    private func makeTransportProtectionPair() -> (TestTransportProtection, TestTransportProtection) {
        let inboundEncryptionKey  = SymmetricKey(size: .bits128)
        let outboundEncryptionKey = SymmetricKey(size: .bits128)
        let inboundMACKey         = SymmetricKey(size: .bits128)
        let outboundMACKey        = SymmetricKey(size: .bits128)

        // Serializer (client-side): out = outbound keys, in = inbound keys
        let serializerProtection = TestTransportProtection(
            initialKeys: .init(
                initialInboundIV: [],
                initialOutboundIV: [],
                inboundEncryptionKey: inboundEncryptionKey,
                outboundEncryptionKey: outboundEncryptionKey,
                inboundMACKey: inboundMACKey,
                outboundMACKey: outboundMACKey
            )
        )

        // Parser (server-side): decrypt what the serializer encrypted, so its
        // inbound keys == serializer's outbound keys and vice-versa.
        let parserProtection = TestTransportProtection(
            initialKeys: .init(
                initialInboundIV: [],
                initialOutboundIV: [],
                inboundEncryptionKey: outboundEncryptionKey,
                outboundEncryptionKey: inboundEncryptionKey,
                inboundMACKey: outboundMACKey,
                outboundMACKey: inboundMACKey
            )
        )

        return (serializerProtection, parserProtection)
    }

    /// Drive a version exchange so both the serializer and parser transition out
    /// of .initialized / .initialized state and are ready for encrypted traffic.
    private func runVersionHandshake(serializer: inout SSHPacketSerializer,
                                     parser: inout SSHPacketParser) throws {
        var buf = ByteBufferAllocator().buffer(capacity: 64)
        try serializer.serialize(message: .version("SSH-2.0-Test_1.0"), to: &buf)
        parser.append(bytes: &buf)
        _ = try parser.nextPacket()
    }

    // MARK: - Round-trip test (encrypted + compressed)

    @available(iOS 13.2, macOS 10.15, watchOS 6.1, tvOS 13.2, *)
    func testEncryptedCompressedRoundTrip() throws {
        let allocator = ByteBufferAllocator()

        var serializer = SSHPacketSerializer()
        var parser     = SSHPacketParser(isServer: true, allocator: allocator)

        // Version handshake — transitions both sides to cleartext state.
        try runVersionHandshake(serializer: &serializer, parser: &parser)

        // Install encryption on both sides.
        let (serializerProtection, parserProtection) = makeTransportProtectionPair()
        serializer.addEncryption(serializerProtection)
        parser.addEncryption(parserProtection)

        // Install compression — the methods under test.
        let compressor   = try ZlibCompressor()
        let decompressor = try ZlibDecompressor()
        serializer.addCompression(compressor)
        parser.addCompression(decompressor)

        // Build the test message.
        let payloadString = String(repeating: "compress me ", count: 20)  // repetition aids compression ratio
        let data = ByteBuffer(string: payloadString)
        let originalMessage = SSHMessage.channelData(.init(recipientChannel: 1, data: data))

        // Serialize (→ compress → encrypt).
        var wireBytes = allocator.buffer(capacity: 256)
        try serializer.serialize(message: originalMessage, to: &wireBytes)

        // Parse (→ decrypt → decompress → parse message).
        parser.append(bytes: &wireBytes)
        let decoded = try parser.nextPacket()

        // Assert round-trip equality.
        guard case .channelData(let result) = decoded else {
            XCTFail("Expected .channelData, got \(String(describing: decoded))")
            return
        }
        XCTAssertEqual(result.recipientChannel, 1)
        XCTAssertEqual(result.data, data, "Decompressed payload must equal the original")
    }
    func testSinglePacketRoundTrip() throws {
        let comp = try ZlibCompressor()
        let decomp = try ZlibDecompressor()
        let payload = ByteBuffer(string: "the quick brown fox jumps over the lazy dog")
        var compressed = try comp.compress(payload)
        let out = try decomp.decompress(&compressed, maxOutput: 64 * 1024)
        XCTAssertEqual(out, payload)
    }

    func testMultiPacketRetainsDictionary() throws {
        let comp = try ZlibCompressor()
        let decomp = try ZlibDecompressor()
        let p = ByteBuffer(string: String(repeating: "abcdefgh", count: 64))
        var c1 = try comp.compress(p)
        var c2 = try comp.compress(p)
        XCTAssertEqual(try decomp.decompress(&c1, maxOutput: 64 * 1024), p)
        XCTAssertEqual(try decomp.decompress(&c2, maxOutput: 64 * 1024), p)
        XCTAssertLessThan(c2.readableBytes, c1.readableBytes, "shared dictionary shrinks the repeat")
    }

    func testDecompressionBombGuard() throws {
        let comp = try ZlibCompressor()
        let decomp = try ZlibDecompressor()
        let big = ByteBuffer(repeating: 0, count: 256 * 1024)
        var compressed = try comp.compress(big)
        XCTAssertThrowsError(try decomp.decompress(&compressed, maxOutput: 64 * 1024)) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .protocolViolation)
        }
    }

    func testCompressionOfferReflectsFlag() {
        XCTAssertEqual(NIOSSHCompressionAlgorithm.disabledOffer, ["none"])
        XCTAssertEqual(NIOSSHCompressionAlgorithm.enabledOffer, ["zlib@openssh.com", "zlib", "none"])
    }
}

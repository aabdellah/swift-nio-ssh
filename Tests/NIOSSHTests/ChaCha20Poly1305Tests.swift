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
import _CryptoExtras

@testable import NIOSSH

/// Golden / reference constants for chacha20-poly1305@openssh.com.
///
/// The OpenSSH full-packet vector below is produced by an INDEPENDENT clean-room Python
/// reference (RFC 8439 ChaCha20 + Poly1305 written from the RFC pseudocode, combined per
/// OpenSSH `PROTOCOL.chacha20poly1305`). That reference is itself validated against three
/// documented public RFC 8439 vectors (§2.4.2 keystream, §2.4.2 ciphertext, §2.5.2 Poly1305)
/// so its primitives are correct independent of the Swift implementation under test. The
/// OpenSSH construction layer (K_2 = first 32 bytes, K_1 = second 32 bytes; IETF 12-byte
/// nonce = 8 zero bytes ‖ seqnr_be32; Poly1305 over len_ct ‖ payload_ct) is taken verbatim
/// from the OpenSSH spec text. These are oracles: if a test fails, the bug is in the Swift
/// code, never in these constants.
private enum GoldenVectors {
    // 64-byte KEX material: K_2 = bytes[0..<32], K_1 = bytes[32..<64].
    // Deterministic pattern key64[i] = (i*7 + 13) & 0xff.
    static let chachaKey64: [UInt8] = [
        0x0d, 0x14, 0x1b, 0x22, 0x29, 0x30, 0x37, 0x3e,
        0x45, 0x4c, 0x53, 0x5a, 0x61, 0x68, 0x6f, 0x76,
        0x7d, 0x84, 0x8b, 0x92, 0x99, 0xa0, 0xa7, 0xae,
        0xb5, 0xbc, 0xc3, 0xca, 0xd1, 0xd8, 0xdf, 0xe6,
        0xed, 0xf4, 0xfb, 0x02, 0x09, 0x10, 0x17, 0x1e,
        0x25, 0x2c, 0x33, 0x3a, 0x41, 0x48, 0x4f, 0x56,
        0x5d, 0x64, 0x6b, 0x72, 0x79, 0x80, 0x87, 0x8e,
        0x95, 0x9c, 0xa3, 0xaa, 0xb1, 0xb8, 0xbf, 0xc6,
    ]

    static let chachaSeqnr: UInt32 = 3

    // SSH plaintext packet: packet_length(4, BE) ‖ padding_length(1) ‖ payload ‖ padding.
    // payload = "hello" (5), padding_length = 10, padding = 10×0x00, packet_length = 16.
    static let chachaPlaintextPacket: [UInt8] = [
        0x00, 0x00, 0x00, 0x10,                          // packet_length = 16
        0x0a,                                            // padding_length = 10
        0x68, 0x65, 0x6c, 0x6c, 0x6f,                    // "hello"
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 10 padding bytes
    ]

    // len_ct(4) ‖ payload_ct(16) ‖ tag(16) = 36 bytes.
    static let chachaExpectedWire: [UInt8] = [
        0x8d, 0x39, 0x4f, 0xd6,                          // encrypted length
        0x1a, 0xed, 0x13, 0x6d, 0xd8, 0x7f, 0x73, 0xb1,  // encrypted payload (16 bytes)
        0xcb, 0xba, 0xc8, 0x80, 0xaf, 0x95, 0x25, 0x5c,
        0xb9, 0x8f, 0x52, 0x0b, 0xb7, 0x33, 0xa0, 0x11,  // poly1305 tag (16 bytes)
        0x69, 0xb2, 0x0f, 0x29, 0xde, 0xbe, 0xce, 0xa8,
    ]
}

private enum TestKeys {
    /// Build session keys whose inbound and outbound encryption keys are both `key64`.
    static func chacha(key64: [UInt8]) -> NIOSSHSessionKeys {
        let key = SymmetricKey(data: key64)
        return NIOSSHSessionKeys(
            initialInboundIV: [],
            initialOutboundIV: [],
            inboundEncryptionKey: key,
            outboundEncryptionKey: key,
            inboundMACKey: SymmetricKey(data: []),
            outboundMACKey: SymmetricKey(data: [])
        )
    }

    /// Build session keys with distinct inbound/outbound 64-byte keys.
    static func chacha(outbound: [UInt8], inbound: [UInt8]) -> NIOSSHSessionKeys {
        NIOSSHSessionKeys(
            initialInboundIV: [],
            initialOutboundIV: [],
            inboundEncryptionKey: SymmetricKey(data: inbound),
            outboundEncryptionKey: SymmetricKey(data: outbound),
            inboundMACKey: SymmetricKey(data: []),
            outboundMACKey: SymmetricKey(data: [])
        )
    }
}

final class ChaCha20Poly1305Tests: XCTestCase {
    // (a) RFC 8439 §2.4.2 keystream sanity: confirms the IETF 12-byte-nonce + 32-bit-counter
    //     mapping reproduces the reference keystream.
    func testChaCha20IETFKeystreamRFC8439() throws {
        let key = SymmetricKey(data: (0...31).map { UInt8($0) })
        var nonceBytes = [UInt8](repeating: 0, count: 12)
        nonceBytes[7] = 0x4a  // RFC 8439 §2.4.2 nonce 00:00:00:00:00:00:00:4a:00:00:00:00
        let nonce = try Insecure.ChaCha20CTR.Nonce(data: nonceBytes)
        let zero = [UInt8](repeating: 0, count: 64)
        let ks = try Insecure.ChaCha20CTR.encrypt(
            zero, using: key, counter: .init(offset: 1), nonce: nonce
        )
        // First 8 bytes of the RFC 8439 §2.4.2 keystream block (counter=1):
        XCTAssertEqual(Array(ks.prefix(8)), [0x22, 0x4f, 0x51, 0xf3, 0x40, 0x1b, 0xd9, 0xe1])
    }

    // (b) OpenSSH chacha20-poly1305 full-packet golden vector. Pins the K_2/K_1 split order
    //     and the IETF-12-byte-nonce ↔ OpenSSH-DJB-nonce keystream equivalence.
    func testOpenSSHFullPacketGoldenVector() throws {
        let key64 = GoldenVectors.chachaKey64  // K_2(first 32) ‖ K_1(second 32)
        let seqnr = GoldenVectors.chachaSeqnr
        let plaintextPacket = GoldenVectors.chachaPlaintextPacket  // length‖padlen‖payload‖padding
        let expectedWire = GoldenVectors.chachaExpectedWire  // len_ct‖payload_ct‖tag(16)

        let keys = TestKeys.chacha(key64: key64)
        let prot = try ChaCha20Poly1305TransportProtection(initialKeys: keys)
        var buf = ByteBufferAllocator().buffer(bytes: plaintextPacket)
        try prot.encryptPacket(&buf, sequenceNumber: seqnr)
        XCTAssertEqual(
            Array(buf.readableBytesView), expectedWire,
            "Fails if K2/K1 split or IETF-nonce mapping is wrong"
        )
    }

    // ----- Round-trip tests -----

    /// Build a valid SSH plaintext packet (length‖padlen‖payload‖padding) for the given payload.
    private func makePacket(payload: [UInt8], paddingLength: Int) -> [UInt8] {
        precondition(paddingLength >= 4)
        let padding = [UInt8](repeating: 0xAB, count: paddingLength)
        let packetLength = 1 + payload.count + paddingLength
        var packet = [UInt8]()
        packet.append(UInt8((packetLength >> 24) & 0xff))
        packet.append(UInt8((packetLength >> 16) & 0xff))
        packet.append(UInt8((packetLength >> 8) & 0xff))
        packet.append(UInt8(packetLength & 0xff))
        packet.append(UInt8(paddingLength))
        packet.append(contentsOf: payload)
        packet.append(contentsOf: padding)
        return packet
    }

    /// Drive a full encrypt → decryptFirstBlock → decryptAndVerifyRemainingPacket cycle and
    /// return the recovered payload (the part after length+padlen and before padding).
    private func roundTrip(
        _ prot: ChaCha20Poly1305TransportProtection,
        payload: [UInt8],
        paddingLength: Int,
        sequenceNumber: UInt32
    ) throws -> [UInt8] {
        let packet = makePacket(payload: payload, paddingLength: paddingLength)
        var wire = ByteBufferAllocator().buffer(bytes: packet)
        try prot.encryptPacket(&wire, sequenceNumber: sequenceNumber)

        // Decrypt side. decryptFirstBlock reveals the length in place; then verify+decrypt.
        var inbound = wire
        try prot.decryptFirstBlock(&inbound, sequenceNumber: sequenceNumber)
        let recovered = try prot.decryptAndVerifyRemainingPacket(
            &inbound, sequenceNumber: sequenceNumber
        )
        return Array(recovered.readableBytesView)
    }

    func testRoundTripThreeSequentialPackets() throws {
        let keys = TestKeys.chacha(key64: GoldenVectors.chachaKey64)
        let prot = try ChaCha20Poly1305TransportProtection(initialKeys: keys)
        for seqnr: UInt32 in 0..<3 {
            let payload: [UInt8] = [0x10, 0x20, 0x30, UInt8(seqnr), 0x99]
            let recovered = try roundTrip(prot, payload: payload, paddingLength: 6, sequenceNumber: seqnr)
            XCTAssertEqual(recovered, payload, "seqnr \(seqnr) round-trip mismatch")
        }
    }

    func testRoundTripMultiBlockPayload() throws {
        let keys = TestKeys.chacha(key64: GoldenVectors.chachaKey64)
        let prot = try ChaCha20Poly1305TransportProtection(initialKeys: keys)
        // Payload comfortably larger than cipherBlockSize (8) to exercise multiple ChaCha blocks.
        // First (and only) decrypt on this object must use seqnr 0 to honour the decryptFirstBlock
        // lockstep (inboundSequenceNumber starts at 0 and advances only after a verified packet).
        let payload = (0..<200).map { UInt8($0 & 0xff) }
        let recovered = try roundTrip(prot, payload: payload, paddingLength: 7, sequenceNumber: 0)
        XCTAssertEqual(recovered, payload)
    }

    func testRoundTripAfterUpdateKeys() throws {
        let keys = TestKeys.chacha(key64: GoldenVectors.chachaKey64)
        let prot = try ChaCha20Poly1305TransportProtection(initialKeys: keys)

        // Round-trip once on the original keys.
        let payload1: [UInt8] = [0xAA, 0xBB, 0xCC]
        XCTAssertEqual(try roundTrip(prot, payload: payload1, paddingLength: 5, sequenceNumber: 0), payload1)

        // Rekey with a different 64-byte key, then round-trip again.
        let newKey64 = (0..<64).map { UInt8(($0 * 5 + 1) & 0xff) }
        try prot.updateKeys(TestKeys.chacha(key64: newKey64))
        let payload2: [UInt8] = [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02]
        XCTAssertEqual(try roundTrip(prot, payload: payload2, paddingLength: 9, sequenceNumber: 1), payload2)
    }

    func testRoundTripDistinctInboundOutboundKeys() throws {
        // Two endpoints: client encrypts with its outbound key; server decrypts with its
        // inbound key. For a successful round-trip, client.outbound == server.inbound. We model
        // a single endpoint whose outbound and inbound keys differ to confirm the scheme uses the
        // right key on each side (encrypt uses outbound, decrypt uses inbound).
        let outKey = (0..<64).map { UInt8(($0 * 3 + 2) & 0xff) }
        let inKey = (0..<64).map { UInt8(($0 * 11 + 7) & 0xff) }

        // Endpoint A encrypts with outKey.
        let a = try ChaCha20Poly1305TransportProtection(
            initialKeys: TestKeys.chacha(outbound: outKey, inbound: inKey))
        // Endpoint B decrypts; its inbound must equal A's outbound.
        let b = try ChaCha20Poly1305TransportProtection(
            initialKeys: TestKeys.chacha(outbound: inKey, inbound: outKey))

        // seqnr 0: first packet on each object, honouring the decryptFirstBlock lockstep.
        let payload: [UInt8] = [0x55, 0x66, 0x77, 0x88]
        let packet = makePacket(payload: payload, paddingLength: 6)
        var wire = ByteBufferAllocator().buffer(bytes: packet)
        try a.encryptPacket(&wire, sequenceNumber: 0)

        var inbound = wire
        try b.decryptFirstBlock(&inbound, sequenceNumber: 0)
        let recovered = try b.decryptAndVerifyRemainingPacket(&inbound, sequenceNumber: 0)
        XCTAssertEqual(Array(recovered.readableBytesView), payload)
    }

    // ----- Tamper tests -----

    func testTamperedTagThrowsInvalidMACTag() throws {
        let keys = TestKeys.chacha(key64: GoldenVectors.chachaKey64)
        let prot = try ChaCha20Poly1305TransportProtection(initialKeys: keys)
        let packet = makePacket(payload: [0x01, 0x02, 0x03, 0x04], paddingLength: 6)
        var wire = ByteBufferAllocator().buffer(bytes: packet)
        try prot.encryptPacket(&wire, sequenceNumber: 7)

        // Flip the last byte (inside the 16-byte tag).
        var bytes = Array(wire.readableBytesView)
        bytes[bytes.count - 1] ^= 0x01
        var tampered = ByteBufferAllocator().buffer(bytes: bytes)

        try prot.decryptFirstBlock(&tampered, sequenceNumber: 7)
        XCTAssertThrowsError(
            try prot.decryptAndVerifyRemainingPacket(&tampered, sequenceNumber: 7)
        ) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .invalidMACTag)
        }
    }

    func testTamperedCiphertextThrowsInvalidMACTag() throws {
        let keys = TestKeys.chacha(key64: GoldenVectors.chachaKey64)
        let prot = try ChaCha20Poly1305TransportProtection(initialKeys: keys)
        let packet = makePacket(payload: [0x01, 0x02, 0x03, 0x04], paddingLength: 6)
        var wire = ByteBufferAllocator().buffer(bytes: packet)
        try prot.encryptPacket(&wire, sequenceNumber: 8)

        // Flip a byte inside the encrypted payload region (byte index 5: past the 4-byte length).
        var bytes = Array(wire.readableBytesView)
        bytes[5] ^= 0x80
        var tampered = ByteBufferAllocator().buffer(bytes: bytes)

        try prot.decryptFirstBlock(&tampered, sequenceNumber: 8)
        XCTAssertThrowsError(
            try prot.decryptAndVerifyRemainingPacket(&tampered, sequenceNumber: 8)
        ) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .invalidMACTag)
        }
    }

    func testWrongSequenceNumberThrowsInvalidMACTag() throws {
        let keys = TestKeys.chacha(key64: GoldenVectors.chachaKey64)
        let prot = try ChaCha20Poly1305TransportProtection(initialKeys: keys)
        let packet = makePacket(payload: [0x09, 0x08, 0x07], paddingLength: 5)
        var wire = ByteBufferAllocator().buffer(bytes: packet)
        try prot.encryptPacket(&wire, sequenceNumber: 100)

        var inbound = wire
        // The parser feeds the SAME (here deliberately wrong) seqnr to both decrypt hooks. The
        // packet was sealed under seqnr 100; decrypting/verifying under seqnr 101 derives the wrong
        // ChaCha20 keystream and Poly1305 one-time key, so the tag check must fail.
        try prot.decryptFirstBlock(&inbound, sequenceNumber: 101)
        XCTAssertThrowsError(
            try prot.decryptAndVerifyRemainingPacket(&inbound, sequenceNumber: 101)
        ) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .invalidMACTag)
        }
    }

    // ----- Construction sanity -----

    func testRejectsWrongKeySize() {
        // 32-byte key (half of the required 64) must be rejected.
        let shortKey = [UInt8](repeating: 0, count: 32)
        XCTAssertThrowsError(
            try ChaCha20Poly1305TransportProtection(initialKeys: TestKeys.chacha(key64: shortKey))
        ) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .invalidKeySize)
        }
    }

    func testStaticMetadata() {
        XCTAssertEqual(ChaCha20Poly1305TransportProtection.cipherName, "chacha20-poly1305@openssh.com")
        XCTAssertNil(ChaCha20Poly1305TransportProtection.macName)
        XCTAssertEqual(ChaCha20Poly1305TransportProtection.cipherBlockSize, 8)
        XCTAssertEqual(ChaCha20Poly1305TransportProtection.keySizes.encryptionKeySize, 64)
    }

    // ----- Parser lockstep (Task T7) -----
    //
    // These tests drive serializer-produced wire bytes through SSHPacketParser to prove the
    // chacha scheme's internal `inboundSequenceNumber` mirror (used by decryptFirstBlock, which
    // receives no seqnr argument) stays in lockstep with SSHPacketParser.sequenceNumber (which
    // feeds decryptAndVerifyRemainingPacket). chacha's nonce is *derived* from the seqnr, so any
    // drift produces a wrong keystream and a Poly1305 failure — the test cannot pass on drift.

    /// Feed the SSH version line so the parser reaches `cleartextWaitingForLength` (seqnr 0).
    private func feedVersion(to parser: inout SSHPacketParser) throws {
        var version = ByteBufferAllocator().buffer(string: "SSH-2.0-OpenSSH_TEST\r\n")
        parser.append(bytes: &version)
        guard case .some(.version) = try parser.nextPacket() else {
            return XCTFail("expected .version")
        }
        XCTAssertEqual(parser.sequenceNumber, 0)
    }

    /// Build a serializer/parser pair that share a key (serializer.outbound == parser.inbound),
    /// both advanced to the encrypted state at sequence number 0.
    private func makeParserPair() throws -> (SSHPacketSerializer, SSHPacketParser) {
        let keys = TestKeys.chacha(key64: GoldenVectors.chachaKey64)
        var serializer = SSHPacketSerializer()
        var version = ByteBufferAllocator().buffer(capacity: 64)
        try serializer.serialize(message: .version("SSH-2.0-OpenSSH_TEST"), to: &version)
        serializer.addEncryption(try ChaCha20Poly1305TransportProtection(initialKeys: keys))

        var parser = SSHPacketParser(isServer: true, allocator: ByteBufferAllocator())
        try feedVersion(to: &parser)
        parser.addEncryption(try ChaCha20Poly1305TransportProtection(initialKeys: keys))
        return (serializer, parser)
    }

    func testParserMultiPacketRoundTrip() throws {
        var (serializer, parser) = try makeParserPair()

        // Five sequential packets straight through the parser. Both sides start at seqnr 0; the
        // chacha mirror must advance exactly with parser.sequenceNumber for every nonce to match.
        for expected in UInt32(0)..<5 {
            XCTAssertEqual(serializer.sequenceNumber, expected)
            XCTAssertEqual(parser.sequenceNumber, expected)

            var wire = ByteBufferAllocator().buffer(capacity: 128)
            try serializer.serialize(message: .newKeys, to: &wire)
            parser.append(bytes: &wire)

            guard case .some(.newKeys) = try parser.nextPacket() else {
                return XCTFail("packet \(expected) failed to decode (lockstep drift?)")
            }
            XCTAssertEqual(parser.sequenceNumber, expected + 1)
        }
    }

    func testParserLockstepAcrossPartialDelivery() throws {
        // The ONLY path that can desync decryptFirstBlock from decryptAndVerifyRemainingPacket: a
        // packet that arrives in two TCP segments. decryptFirstBlock runs on the first segment
        // (revealing the provisional length) WITHOUT advancing parser.sequenceNumber; the body
        // arrives later and decryptAndVerifyRemainingPacket must use the SAME seqnr. We sandwich a
        // split packet between whole ones to prove the mirror does not over- or under-advance.
        var (serializer, parser) = try makeParserPair()

        // Packet 0 (seqnr 0), whole.
        var w0 = ByteBufferAllocator().buffer(capacity: 128)
        try serializer.serialize(message: .newKeys, to: &w0)
        parser.append(bytes: &w0)
        guard case .some(.newKeys) = try parser.nextPacket() else { return XCTFail("packet 0") }
        XCTAssertEqual(parser.sequenceNumber, 1)

        // Packet 1 (seqnr 1), delivered as length-block first, then the remainder.
        var w1 = ByteBufferAllocator().buffer(capacity: 128)
        try serializer.serialize(message: .newKeys, to: &w1)
        // chacha cipherBlockSize is 8 -> decryptFirstBlock fires once >= 8 bytes are present.
        var head = w1.readSlice(length: 8)!
        parser.append(bytes: &head)
        XCTAssertNil(try parser.nextPacket(), "incomplete packet must yield nil")
        XCTAssertEqual(parser.sequenceNumber, 1, "seqnr must NOT advance on a partial packet")
        parser.append(bytes: &w1)  // remainder
        guard case .some(.newKeys) = try parser.nextPacket() else {
            return XCTFail("split packet 1 failed to decode (decryptFirstBlock/verify seqnr drift)")
        }
        XCTAssertEqual(parser.sequenceNumber, 2)

        // Packet 2 (seqnr 2), whole — confirms the mirror lands on 2, not 1 or 3, after the split.
        var w2 = ByteBufferAllocator().buffer(capacity: 128)
        try serializer.serialize(message: .newKeys, to: &w2)
        parser.append(bytes: &w2)
        guard case .some(.newKeys) = try parser.nextPacket() else { return XCTFail("packet 2") }
        XCTAssertEqual(parser.sequenceNumber, 3)
    }

    func testParserEncryptionAddedAfterPlaintextPackets() throws {
        // Regression: in a real handshake, several PLAINTEXT packets (version, KEXINIT, KEXECDH,
        // NEWKEYS) are exchanged before encryption is installed, so addEncryption happens while the
        // parser's sequence number is already > 0. chacha's decryptFirstBlock derives its nonce
        // from a sequence-number mirror; if that mirror assumes the first encrypted packet is
        // seqnr 0 it builds the wrong K_1 keystream, mis-decrypts the length field, and the parser
        // either mis-frames or waits forever. This reproduces the EndToEndTests hang in isolation.
        let keys = TestKeys.chacha(key64: GoldenVectors.chachaKey64)
        var serializer = SSHPacketSerializer()
        var version = ByteBufferAllocator().buffer(capacity: 64)
        try serializer.serialize(message: .version("SSH-2.0-OpenSSH_TEST"), to: &version)

        var parser = SSHPacketParser(isServer: true, allocator: ByteBufferAllocator())
        try feedVersion(to: &parser)

        // Three plaintext packets to advance BOTH sides to sequence number 3 before encryption.
        for _ in 0..<3 {
            var w = ByteBufferAllocator().buffer(capacity: 128)
            try serializer.serialize(message: .newKeys, to: &w)
            parser.append(bytes: &w)
            guard case .some(.newKeys) = try parser.nextPacket() else { return XCTFail("plaintext") }
        }
        XCTAssertEqual(serializer.sequenceNumber, 3)
        XCTAssertEqual(parser.sequenceNumber, 3)

        // Install encryption now (seqnr 3 on both sides), then exchange an encrypted packet.
        serializer.addEncryption(try ChaCha20Poly1305TransportProtection(initialKeys: keys))
        parser.addEncryption(try ChaCha20Poly1305TransportProtection(initialKeys: keys))

        var enc = ByteBufferAllocator().buffer(capacity: 128)
        try serializer.serialize(message: .newKeys, to: &enc)  // first ENCRYPTED packet, seqnr 3
        parser.append(bytes: &enc)
        guard case .some(.newKeys) = try parser.nextPacket() else {
            return XCTFail("first encrypted packet failed to decode (decryptFirstBlock nonce drift)")
        }
        XCTAssertEqual(parser.sequenceNumber, 4)
    }

    func testSerializerPreservesPriorBytesInOutboundBuffer() throws {
        // Regression: SSHPacketSerializer hands encryptPacket a buffer whose READABLE region is the
        // new packet but which may carry earlier, not-yet-flushed bytes BEFORE the reader index
        // (it does a moveReaderIndex(to: writerIndex) dance and restores the reader afterwards). An
        // encryptPacket that calls buffer.clear() and rewrites from index 0 destroys those prior
        // bytes and emits a buffer whose restored reader index lands past the writer index -> zero
        // readable bytes reach the peer's parser. This was the true cause of the EndToEnd handshake
        // hang. The fix overwrites the readable region in place; this test pins it.
        let keys = TestKeys.chacha(key64: GoldenVectors.chachaKey64)
        var serializer = SSHPacketSerializer()
        var outbound = ByteBufferAllocator().buffer(capacity: 256)
        try serializer.serialize(message: .version("SSH-2.0-OpenSSH_TEST"), to: &outbound)
        serializer.addEncryption(try ChaCha20Poly1305TransportProtection(initialKeys: keys))

        // Serialize TWO encrypted packets back-to-back into the SAME outbound buffer WITHOUT
        // flushing between them. The version-line bytes plus the first encrypted packet sit before
        // the reader index when the second packet is encrypted, exercising the in-place contract.
        try serializer.serialize(message: .newKeys, to: &outbound)  // seqnr 0
        try serializer.serialize(message: .newKeys, to: &outbound)  // seqnr 1

        // The peer parses the single coalesced delivery: version line, then both encrypted packets.
        var parser = SSHPacketParser(isServer: true, allocator: ByteBufferAllocator())
        parser.append(bytes: &outbound)
        guard case .some(.version) = try parser.nextPacket() else { return XCTFail("version") }
        parser.addEncryption(try ChaCha20Poly1305TransportProtection(initialKeys: keys))
        guard case .some(.newKeys) = try parser.nextPacket() else {
            return XCTFail("first encrypted packet lost (clear() discarded prior outbound bytes?)")
        }
        guard case .some(.newKeys) = try parser.nextPacket() else {
            return XCTFail("second encrypted packet lost (clear() discarded prior outbound bytes?)")
        }
        XCTAssertEqual(parser.sequenceNumber, 2)
    }
}

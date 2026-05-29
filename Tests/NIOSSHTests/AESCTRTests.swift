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

final class AESCTRTests: XCTestCase {
    // MARK: - Primitive golden vectors (external oracles)

    // NIST SP 800-38A F.5.1 AES-128-CTR, first block.
    // Key   = 2b7e151628aed2a6abf7158809cf4f3c
    // ICTR  = f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
    // PT    = 6bc1bee22e409f96e93d7e117393172a
    // CT    = 874d6191b620e3261bef6864990db6ce
    func testAES128CTRKeystreamNIST() throws {
        let key = SymmetricKey(data: [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
        ])
        let iv: [UInt8] = (0xf0...0xff).map { UInt8($0) }  // F.5.1 initial counter
        let pt: [UInt8] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        ]
        let ct = try AES._CTR.encrypt(pt, using: key, nonce: .init(nonceBytes: iv))
        XCTAssertEqual(
            Array(ct),
            [
                0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26,
                0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce,
            ]
        )
    }

    // NIST SP 800-38A F.5.1 multi-block: confirms the 128-bit big-endian counter advance across
    // blocks (the fourth block uses the counter f0...fc f0...ff, i.e. low byte wraps 0xff -> 0x00
    // with carry). PT/CT are blocks 1..4 of the published vector.
    func testAES128CTRMultiBlockNIST() throws {
        let key = SymmetricKey(data: [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
        ])
        let iv: [UInt8] = (0xf0...0xff).map { UInt8($0) }
        let pt: [UInt8] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
            0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
            0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
            0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
        ]
        let ct: [UInt8] = [
            0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce,
            0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff, 0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff,
            0x5a, 0xe4, 0xdf, 0x3e, 0xdb, 0xd5, 0xd3, 0x5e, 0x5b, 0x4f, 0x09, 0x02, 0x0d, 0xb0, 0x3e, 0xab,
            0x1e, 0x03, 0x1d, 0xda, 0x2f, 0xbe, 0x03, 0xd1, 0x79, 0x21, 0x70, 0xa0, 0xf3, 0x00, 0x9c, 0xee,
        ]
        let out = try AES._CTR.encrypt(pt, using: key, nonce: .init(nonceBytes: iv))
        XCTAssertEqual(Array(out), ct)
    }

    // RFC 4231 Test Case 2 HMAC-SHA-256.
    func testHMACSHA256RFC4231() {
        let key = SymmetricKey(data: Array("Jefe".utf8))
        let mac = HMAC<SHA256>.authenticationCode(for: Array("what do ya want for nothing?".utf8), using: key)
        XCTAssertEqual(
            Array(mac).map { String(format: "%02x", $0) }.joined(),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        )
    }

    // RFC 4231 Test Case 2 HMAC-SHA-512.
    func testHMACSHA512RFC4231() {
        let key = SymmetricKey(data: Array("Jefe".utf8))
        let mac = HMAC<SHA512>.authenticationCode(for: Array("what do ya want for nothing?".utf8), using: key)
        XCTAssertEqual(
            Array(mac).map { String(format: "%02x", $0) }.joined(),
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
        )
    }

    // MARK: - Helpers

    /// Build session keys of the sizes a given scheme demands. IVs are 16 bytes (CTR counter).
    private func makeKeys<P: AESCTRTransportProtection>(
        for _: P.Type,
        salt: UInt8 = 0
    ) -> NIOSSHSessionKeys {
        let encSize = P.keySizes.encryptionKeySize
        let macSize = P.keySizes.macKeySize
        func bytes(_ count: Int, _ base: UInt8) -> [UInt8] {
            (0..<count).map { UInt8(($0 + Int(base) + Int(salt)) & 0xff) }
        }
        return NIOSSHSessionKeys(
            initialInboundIV: bytes(16, 0x10),
            initialOutboundIV: bytes(16, 0x20),
            inboundEncryptionKey: SymmetricKey(data: bytes(encSize, 0x30)),
            outboundEncryptionKey: SymmetricKey(data: bytes(encSize, 0x40)),
            inboundMACKey: SymmetricKey(data: bytes(macSize, 0x50)),
            outboundMACKey: SymmetricKey(data: bytes(macSize, 0x60))
        )
    }

    /// Cross the inbound/outbound roles so that the "client" outbound is the "server" inbound and
    /// vice versa. Lets us encrypt with one instance and decrypt with the matching peer instance.
    private func crossedKeys(_ keys: NIOSSHSessionKeys) -> NIOSSHSessionKeys {
        NIOSSHSessionKeys(
            initialInboundIV: keys.initialOutboundIV,
            initialOutboundIV: keys.initialInboundIV,
            inboundEncryptionKey: keys.outboundEncryptionKey,
            outboundEncryptionKey: keys.inboundEncryptionKey,
            inboundMACKey: keys.outboundMACKey,
            outboundMACKey: keys.inboundMACKey
        )
    }

    /// Build a valid plaintext SSH packet body: length(4) ‖ padlen(1) ‖ payload ‖ padding.
    /// blockSize aligns the (padlen ‖ payload ‖ padding) for E&M and the whole (len‖...) tail per
    /// RFC 4253 §6, but for these unit tests we only need a self-consistent, strippable body.
    private func makePlaintextPacket(payload: [UInt8], blockSize: Int, lengthEncrypted: Bool) -> [UInt8] {
        // padlen >= 4. We size padding so that the encrypted region is a block multiple.
        // Region that must be block-aligned:
        //   E&M (lengthEncrypted=true):  4 + 1 + payload + padding
        //   ETM (lengthEncrypted=false): 1 + payload + padding (length is cleartext)
        let prefix = lengthEncrypted ? 4 + 1 : 1
        var paddingLength = blockSize - ((prefix + payload.count) % blockSize)
        if paddingLength < 4 { paddingLength += blockSize }
        let padding = (0..<paddingLength).map { UInt8(0xC0 &+ $0) }
        let packetLength = UInt32(1 + payload.count + paddingLength)  // padlen byte + payload + padding
        var out = [UInt8]()
        out.append(UInt8((packetLength >> 24) & 0xff))
        out.append(UInt8((packetLength >> 16) & 0xff))
        out.append(UInt8((packetLength >> 8) & 0xff))
        out.append(UInt8(packetLength & 0xff))
        out.append(UInt8(paddingLength))
        out.append(contentsOf: payload)
        out.append(contentsOf: padding)
        return out
    }

    /// Run one round-trip: enc instance encrypts, dec instance decrypts+verifies, returns the
    /// recovered payload.
    private func roundTrip<P: AESCTRTransportProtection>(
        enc: P,
        dec: P,
        payload: [UInt8],
        seq: UInt32
    ) throws -> [UInt8] {
        let packet = makePlaintextPacket(
            payload: payload,
            blockSize: P.cipherBlockSize,
            lengthEncrypted: enc.lengthEncrypted
        )
        var wire = ByteBufferAllocator().buffer(bytes: packet)
        try enc.encryptPacket(&wire, sequenceNumber: seq)

        // Decrypt: peer reveals length, then verifies + decrypts the remainder.
        try dec.decryptFirstBlock(&wire)
        let body = try dec.decryptAndVerifyRemainingPacket(&wire, sequenceNumber: seq)
        return Array(body.readableBytesView)
    }

    // MARK: - Per-scheme matrix

    /// Exercises a single concrete scheme: static-property assertions, a 3-packet round-trip with
    /// incrementing seqnr, a multi-block payload, a post-rekey round-trip, and three tamper vectors.
    private func runScheme<P: AESCTRTransportProtection>(
        _ type: P.Type,
        expectMACBytes: Int,
        expectLengthEncrypted: Bool,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        let keys = makeKeys(for: type)
        let enc = try P(initialKeys: keys)
        let dec = try P(initialKeys: crossedKeys(keys))

        XCTAssertEqual(P.cipherBlockSize, 16, "cipherBlockSize", file: file, line: line)
        XCTAssertEqual(enc.macBytes, expectMACBytes, "macBytes", file: file, line: line)
        XCTAssertEqual(enc.lengthEncrypted, expectLengthEncrypted, "lengthEncrypted", file: file, line: line)

        // 3 packets, seqnr 0,1,2 — counters must advance in lockstep on both sides.
        for seq in UInt32(0)..<3 {
            let payload = (0..<(16 + Int(seq))).map { UInt8(($0 + Int(seq) * 7) & 0xff) }
            let recovered = try roundTrip(enc: enc, dec: dec, payload: payload, seq: seq)
            XCTAssertEqual(recovered, payload, "round-trip seq \(seq)", file: file, line: line)
        }

        // Multi-block payload (> one cipher block).
        do {
            let payload = (0..<200).map { UInt8(($0 * 3 + 1) & 0xff) }
            let recovered = try roundTrip(enc: enc, dec: dec, payload: payload, seq: 3)
            XCTAssertEqual(recovered, payload, "multi-block round-trip", file: file, line: line)
        }

        // Rekey: fresh keys reset the counters; round-trip must still succeed.
        let keys2 = makeKeys(for: type, salt: 0x77)
        try enc.updateKeys(keys2)
        try dec.updateKeys(crossedKeys(keys2))
        do {
            let payload = (0..<48).map { UInt8(($0 + 9) & 0xff) }
            let recovered = try roundTrip(enc: enc, dec: dec, payload: payload, seq: 0)
            XCTAssertEqual(recovered, payload, "post-rekey round-trip", file: file, line: line)
        }

        // Tamper vectors — each on a fresh pair so counter state is clean.
        try runTamperTests(type, file: file, line: line)
    }

    private func runTamperTests<P: AESCTRTransportProtection>(
        _ type: P.Type,
        file: StaticString,
        line: UInt
    ) throws {
        let payload = (0..<24).map { UInt8(($0 + 5) & 0xff) }

        // Tamper the MAC tag (last byte).
        do {
            let keys = makeKeys(for: type, salt: 0x01)
            let enc = try P(initialKeys: keys)
            let dec = try P(initialKeys: crossedKeys(keys))
            let packet = makePlaintextPacket(payload: payload, blockSize: P.cipherBlockSize, lengthEncrypted: enc.lengthEncrypted)
            var wire = ByteBufferAllocator().buffer(bytes: packet)
            try enc.encryptPacket(&wire, sequenceNumber: 0)
            let last = wire.writerIndex - 1
            var b = wire.getInteger(at: last, as: UInt8.self)!
            b ^= 0xff
            wire.setInteger(b, at: last)
            try dec.decryptFirstBlock(&wire)
            XCTAssertThrowsError(try dec.decryptAndVerifyRemainingPacket(&wire, sequenceNumber: 0), "tampered tag", file: file, line: line) {
                XCTAssertEqual(($0 as? NIOSSHError)?.type, .invalidMACTag, file: file, line: line)
            }
        }

        // Tamper a ciphertext byte (a byte inside the encrypted region, just after the length).
        do {
            let keys = makeKeys(for: type, salt: 0x02)
            let enc = try P(initialKeys: keys)
            let dec = try P(initialKeys: crossedKeys(keys))
            let packet = makePlaintextPacket(payload: payload, blockSize: P.cipherBlockSize, lengthEncrypted: enc.lengthEncrypted)
            var wire = ByteBufferAllocator().buffer(bytes: packet)
            try enc.encryptPacket(&wire, sequenceNumber: 0)
            // Index 5 lands inside the ciphertext for both ETM (cleartext len is bytes 0..3) and E&M.
            let idx = wire.readerIndex + 5
            var b = wire.getInteger(at: idx, as: UInt8.self)!
            b ^= 0xff
            wire.setInteger(b, at: idx)
            try dec.decryptFirstBlock(&wire)
            XCTAssertThrowsError(try dec.decryptAndVerifyRemainingPacket(&wire, sequenceNumber: 0), "tampered ciphertext", file: file, line: line) {
                XCTAssertEqual(($0 as? NIOSSHError)?.type, .invalidMACTag, file: file, line: line)
            }
        }

        // ETM-only: tamper the cleartext length field (bytes 0..3) — it is MAC'd, so it must fail.
        if !P.isETM == false {  // i.e. isETM == true
            let keys = makeKeys(for: type, salt: 0x03)
            let enc = try P(initialKeys: keys)
            let dec = try P(initialKeys: crossedKeys(keys))
            let packet = makePlaintextPacket(payload: payload, blockSize: P.cipherBlockSize, lengthEncrypted: enc.lengthEncrypted)
            var wire = ByteBufferAllocator().buffer(bytes: packet)
            try enc.encryptPacket(&wire, sequenceNumber: 0)
            let idx = wire.readerIndex + 3  // low byte of the cleartext length
            var b = wire.getInteger(at: idx, as: UInt8.self)!
            b ^= 0x01
            wire.setInteger(b, at: idx)
            try dec.decryptFirstBlock(&wire)
            XCTAssertThrowsError(try dec.decryptAndVerifyRemainingPacket(&wire, sequenceNumber: 0), "tampered ETM length", file: file, line: line) {
                XCTAssertEqual(($0 as? NIOSSHError)?.type, .invalidMACTag, file: file, line: line)
            }
        }
    }

    // The 12 cross-product schemes.
    func testAES128CTR_HMACSHA256ETM() throws {
        try runScheme(AES128CTR_HMACSHA256ETM.self, expectMACBytes: 32, expectLengthEncrypted: false)
    }
    func testAES128CTR_HMACSHA512ETM() throws {
        try runScheme(AES128CTR_HMACSHA512ETM.self, expectMACBytes: 64, expectLengthEncrypted: false)
    }
    func testAES128CTR_HMACSHA256() throws {
        try runScheme(AES128CTR_HMACSHA256.self, expectMACBytes: 32, expectLengthEncrypted: true)
    }
    func testAES128CTR_HMACSHA512() throws {
        try runScheme(AES128CTR_HMACSHA512.self, expectMACBytes: 64, expectLengthEncrypted: true)
    }
    func testAES192CTR_HMACSHA256ETM() throws {
        try runScheme(AES192CTR_HMACSHA256ETM.self, expectMACBytes: 32, expectLengthEncrypted: false)
    }
    func testAES192CTR_HMACSHA512ETM() throws {
        try runScheme(AES192CTR_HMACSHA512ETM.self, expectMACBytes: 64, expectLengthEncrypted: false)
    }
    func testAES192CTR_HMACSHA256() throws {
        try runScheme(AES192CTR_HMACSHA256.self, expectMACBytes: 32, expectLengthEncrypted: true)
    }
    func testAES192CTR_HMACSHA512() throws {
        try runScheme(AES192CTR_HMACSHA512.self, expectMACBytes: 64, expectLengthEncrypted: true)
    }
    func testAES256CTR_HMACSHA256ETM() throws {
        try runScheme(AES256CTR_HMACSHA256ETM.self, expectMACBytes: 32, expectLengthEncrypted: false)
    }
    func testAES256CTR_HMACSHA512ETM() throws {
        try runScheme(AES256CTR_HMACSHA512ETM.self, expectMACBytes: 64, expectLengthEncrypted: false)
    }
    func testAES256CTR_HMACSHA256() throws {
        try runScheme(AES256CTR_HMACSHA256.self, expectMACBytes: 32, expectLengthEncrypted: true)
    }
    func testAES256CTR_HMACSHA512() throws {
        try runScheme(AES256CTR_HMACSHA512.self, expectMACBytes: 64, expectLengthEncrypted: true)
    }

    // Cross-product name/macName sanity (the negotiation table in Task 6 depends on these).
    func testSchemeNamesAndMACNames() {
        XCTAssertEqual(AES128CTR_HMACSHA256ETM.cipherName, "aes128-ctr")
        XCTAssertEqual(AES128CTR_HMACSHA256ETM.macName, "hmac-sha2-256-etm@openssh.com")
        XCTAssertEqual(AES192CTR_HMACSHA512ETM.cipherName, "aes192-ctr")
        XCTAssertEqual(AES192CTR_HMACSHA512ETM.macName, "hmac-sha2-512-etm@openssh.com")
        XCTAssertEqual(AES256CTR_HMACSHA256.cipherName, "aes256-ctr")
        XCTAssertEqual(AES256CTR_HMACSHA256.macName, "hmac-sha2-256")
        XCTAssertEqual(AES256CTR_HMACSHA512.macName, "hmac-sha2-512")
    }

    // Wrong key size is rejected.
    func testInvalidKeySizeRejected() {
        // aes256-ctr scheme fed a 128-bit key.
        let badKeys = NIOSSHSessionKeys(
            initialInboundIV: [UInt8](repeating: 0, count: 16),
            initialOutboundIV: [UInt8](repeating: 0, count: 16),
            inboundEncryptionKey: SymmetricKey(data: [UInt8](repeating: 0, count: 16)),
            outboundEncryptionKey: SymmetricKey(data: [UInt8](repeating: 0, count: 16)),
            inboundMACKey: SymmetricKey(data: [UInt8](repeating: 0, count: 32)),
            outboundMACKey: SymmetricKey(data: [UInt8](repeating: 0, count: 32))
        )
        XCTAssertThrowsError(try AES256CTR_HMACSHA256.init(initialKeys: badKeys)) {
            XCTAssertEqual(($0 as? NIOSSHError)?.type, .invalidKeySize)
        }
    }

    // Wrong IV length (not 16) is rejected.
    func testInvalidNonceLengthRejected() {
        let badKeys = NIOSSHSessionKeys(
            initialInboundIV: [UInt8](repeating: 0, count: 12),  // GCM-shaped, wrong for CTR
            initialOutboundIV: [UInt8](repeating: 0, count: 12),
            inboundEncryptionKey: SymmetricKey(data: [UInt8](repeating: 0, count: 16)),
            outboundEncryptionKey: SymmetricKey(data: [UInt8](repeating: 0, count: 16)),
            inboundMACKey: SymmetricKey(data: [UInt8](repeating: 0, count: 32)),
            outboundMACKey: SymmetricKey(data: [UInt8](repeating: 0, count: 32))
        )
        XCTAssertThrowsError(try AES128CTR_HMACSHA256.init(initialKeys: badKeys)) {
            XCTAssertEqual(($0 as? NIOSSHError)?.type, .invalidNonceLength)
        }
    }
}

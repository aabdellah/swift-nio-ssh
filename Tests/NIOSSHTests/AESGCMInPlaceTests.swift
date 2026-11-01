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

/// Holds the in-place AES-GCM road (OS 27) and the copying road (OS 26) byte-for-byte equal: both are called
/// directly, so a host on either OS exercises the one its `#available` branch does not pick.
final class AESGCMInPlaceTests: XCTestCase {
    private typealias Transport = AESGCMTransportProtection

    /// `[length][padding length][payload][padding]`, the body a multiple of the block size.
    private func makePacket(payload: [UInt8]) -> ByteBuffer {
        var paddingLength = 16 - ((1 + payload.count) % 16)
        if paddingLength < 4 { paddingLength += 16 }
        let bodyLength = 1 + payload.count + paddingLength
        var packet = ByteBufferAllocator().buffer(capacity: 4 + bodyLength + 16)
        packet.writeInteger(UInt32(bodyLength))
        packet.writeInteger(UInt8(paddingLength))
        packet.writeBytes(payload)
        packet.writeBytes((0..<paddingLength).map { UInt8(truncatingIfNeeded: $0 &* 37) })
        return packet
    }

    private let payloads: [[UInt8]] = [
        [],
        [0x15],
        Array(repeating: 0xA5, count: 11),
        (0..<255).map { UInt8($0) },
        (0..<32_768).map { UInt8(truncatingIfNeeded: $0 &* 131) },
    ]

    func testInPlaceSealMatchesCopyingSeal() throws {
        guard #available(macOS 27, iOS 27, tvOS 27, watchOS 27, visionOS 27, *) else {
            throw XCTSkip("CryptoKit in-place AEAD needs OS 27")
        }
        for keySize in [SymmetricKeySize.bits128, .bits256] {
            let key = SymmetricKey(size: keySize)
            let nonce = AES.GCM.Nonce()
            for payload in self.payloads {
                let plain = self.makePacket(payload: payload)
                var copying = plain
                var inPlace = plain
                try Transport.sealCopying(&copying, using: key, nonce: nonce)
                try Transport.sealInPlace(&inPlace, using: key, nonce: nonce)
                XCTAssertEqual(inPlace, copying, "payload \(payload.count) bytes")
                XCTAssertEqual(inPlace.readableBytes, plain.readableBytes + 16)
                XCTAssertNotEqual(
                    inPlace.getSlice(at: 4, length: plain.readableBytes - 4),
                    plain.getSlice(at: 4, length: plain.readableBytes - 4)
                )
            }
        }
    }

    func testEachRoadOpensTheOthersPacket() throws {
        guard #available(macOS 27, iOS 27, tvOS 27, watchOS 27, visionOS 27, *) else {
            throw XCTSkip("CryptoKit in-place AEAD needs OS 27")
        }
        let key = SymmetricKey(size: .bits256)
        let nonce = AES.GCM.Nonce()
        for payload in self.payloads {
            let plain = self.makePacket(payload: payload)
            let bodyLength = plain.readableBytes - 4

            var sealedByCopying = plain
            try Transport.sealCopying(&sealedByCopying, using: key, nonce: nonce)
            try Transport.openInPlace(&sealedByCopying, using: key, nonce: nonce)
            XCTAssertEqual(
                try Transport.consumeOpenedPacket(&sealedByCopying, plaintextLength: bodyLength),
                ByteBuffer(bytes: payload)
            )
            XCTAssertEqual(sealedByCopying.readableBytes, 0)

            var sealedInPlace = plain
            try Transport.sealInPlace(&sealedInPlace, using: key, nonce: nonce)
            try Transport.openCopying(&sealedInPlace, using: key, nonce: nonce)
            XCTAssertEqual(
                try Transport.consumeOpenedPacket(&sealedInPlace, plaintextLength: bodyLength),
                ByteBuffer(bytes: payload)
            )
            XCTAssertEqual(sealedInPlace.readableBytes, 0)
        }
    }

    func testCopyingRoadRoundTrips() throws {
        let key = SymmetricKey(size: .bits128)
        let nonce = AES.GCM.Nonce()
        for payload in self.payloads {
            var packet = self.makePacket(payload: payload)
            let bodyLength = packet.readableBytes - 4
            try Transport.sealCopying(&packet, using: key, nonce: nonce)
            try Transport.openCopying(&packet, using: key, nonce: nonce)
            XCTAssertEqual(
                try Transport.consumeOpenedPacket(&packet, plaintextLength: bodyLength),
                ByteBuffer(bytes: payload)
            )
        }
    }

    func testBothRoadsRejectTampering() throws {
        guard #available(macOS 27, iOS 27, tvOS 27, watchOS 27, visionOS 27, *) else {
            throw XCTSkip("CryptoKit in-place AEAD needs OS 27")
        }
        let key = SymmetricKey(size: .bits128)
        let nonce = AES.GCM.Nonce()
        var sealed = self.makePacket(payload: Array(repeating: 0x42, count: 40))
        try Transport.sealCopying(&sealed, using: key, nonce: nonce)

        // The cleartext length (authenticated data), a body byte, and a tag byte.
        for offset in [1, 4 + 7, sealed.readableBytes - 1] {
            var tampered = sealed
            tampered.setInteger(tampered.getInteger(at: offset, as: UInt8.self)! ^ 0x01, at: offset)

            var forInPlace = tampered
            XCTAssertThrowsError(try Transport.openInPlace(&forInPlace, using: key, nonce: nonce), "offset \(offset)")
            var forCopying = tampered
            XCTAssertThrowsError(try Transport.openCopying(&forCopying, using: key, nonce: nonce), "offset \(offset)")
        }

        var wrongNonce = sealed
        XCTAssertThrowsError(try Transport.openInPlace(&wrongNonce, using: key, nonce: AES.GCM.Nonce()))
        var wrongKey = sealed
        XCTAssertThrowsError(try Transport.openInPlace(&wrongKey, using: SymmetricKey(size: .bits128), nonce: nonce))
    }
}

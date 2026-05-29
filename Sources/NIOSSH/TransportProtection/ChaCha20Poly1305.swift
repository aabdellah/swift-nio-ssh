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
import Foundation
import NIOCore
import _CryptoExtras

/// `chacha20-poly1305@openssh.com` (OpenSSH `PROTOCOL.chacha20poly1305`).
///
/// Two independent ChaCha20 keys are taken from the 64 bytes of KEX material:
///   - `K_2` = the first 32 bytes  -> payload cipher + Poly1305 one-time key
///   - `K_1` = the second 32 bytes -> packet-length-field cipher
///
/// The IETF ChaCha20 nonce (12 bytes) is the DJB 8-byte nonce — the packet sequence number
/// encoded as a uint64 under SSH wire (big-endian) rules — prefixed by the four high bytes of
/// the DJB 8-byte block counter (always zero for the block counters 0 and 1 OpenSSH uses). The
/// sequence number fits in a uint32, so the resulting 12-byte nonce is
/// `00 00 00 00 00 00 00 00 ‖ seqnr_be32`.
final class ChaCha20Poly1305TransportProtection: NIOSSHTransportProtection, _NIOSSHSendableMetatype {
    static let cipherName = "chacha20-poly1305@openssh.com"
    static let macName: String? = nil
    static let cipherBlockSize = 8
    static let keySizes = ExpectedKeySizes(ivSize: 0, encryptionKeySize: 64, macKeySize: 0)
    let macBytes = 16
    let lengthEncrypted = true

    private var outboundK2: SymmetricKey  // payload + poly key
    private var outboundK1: SymmetricKey  // length
    private var inboundK2: SymmetricKey
    private var inboundK1: SymmetricKey

    required init(initialKeys: NIOSSHSessionKeys) throws {
        guard initialKeys.outboundEncryptionKey.bitCount == 64 * 8,
            initialKeys.inboundEncryptionKey.bitCount == 64 * 8
        else {
            throw NIOSSHError.invalidKeySize
        }
        (outboundK2, outboundK1) = Self.split(initialKeys.outboundEncryptionKey)
        (inboundK2, inboundK1) = Self.split(initialKeys.inboundEncryptionKey)
    }

    func updateKeys(_ newKeys: NIOSSHSessionKeys) throws {
        guard newKeys.outboundEncryptionKey.bitCount == 64 * 8,
            newKeys.inboundEncryptionKey.bitCount == 64 * 8
        else {
            throw NIOSSHError.invalidKeySize
        }
        (outboundK2, outboundK1) = Self.split(newKeys.outboundEncryptionKey)
        (inboundK2, inboundK1) = Self.split(newKeys.inboundEncryptionKey)
    }

    private static func split(_ key: SymmetricKey) -> (SymmetricKey, SymmetricKey) {
        let bytes = key.withUnsafeBytes { Array($0) }  // 64 bytes
        return (SymmetricKey(data: bytes[0..<32]), SymmetricKey(data: bytes[32..<64]))
    }

    private static func nonce(_ seqnr: UInt32) throws -> Insecure.ChaCha20CTR.Nonce {
        var n = [UInt8](repeating: 0, count: 12)
        n[8] = UInt8((seqnr >> 24) & 0xff)
        n[9] = UInt8((seqnr >> 16) & 0xff)
        n[10] = UInt8((seqnr >> 8) & 0xff)
        n[11] = UInt8(seqnr & 0xff)
        return try Insecure.ChaCha20CTR.Nonce(data: n)
    }

    private func polyKey(_ k2: SymmetricKey, _ nonce: Insecure.ChaCha20CTR.Nonce) throws -> [UInt8] {
        let ks = try Insecure.ChaCha20CTR.encrypt(
            [UInt8](repeating: 0, count: 32),
            using: k2, counter: .init(offset: 0), nonce: nonce)
        return Array(ks.prefix(32))
    }

    func decryptFirstBlock(_ source: inout ByteBuffer, sequenceNumber: UInt32) throws {
        // Reveal the 4-byte (provisional) length: CTR-decrypt the first 4 bytes under K_1,
        // counter 0, in place — WITHOUT consuming K_2 keystream. The Poly1305 check happens
        // later in decryptAndVerifyRemainingPacket; the parser bounds length+macBytes meanwhile.
        // The nonce is derived from the parser's authoritative `sequenceNumber` (the same value the
        // matching decryptAndVerifyRemainingPacket receives), so this is correct even when
        // encryption is installed mid-handshake at a non-zero sequence number.
        guard source.readableBytes >= 4 else { return }
        let nonce = try Self.nonce(sequenceNumber)
        let lenCT = Array(source.readableBytesView.prefix(4))
        let lenPT = try Insecure.ChaCha20CTR.encrypt(
            lenCT, using: inboundK1, counter: .init(offset: 0), nonce: nonce)
        source.setBytes(Array(lenPT.prefix(4)), at: source.readerIndex)
    }

    func decryptAndVerifyRemainingPacket(_ source: inout ByteBuffer, sequenceNumber: UInt32) throws
        -> ByteBuffer
    {
        let nonce = try Self.nonce(sequenceNumber)
        guard source.readableBytes >= 4 + 16 else { throw NIOSSHError.invalidEncryptedPacketLength }
        // decryptFirstBlock already decrypted the 4 length bytes IN PLACE, but Poly1305
        // authenticates the CIPHERTEXT. Recompute lenCT by re-encrypting the plaintext length
        // (CTR is symmetric).
        let lenPT4 = Array(source.readableBytesView.prefix(4))
        let lenCT = try Insecure.ChaCha20CTR.encrypt(
            lenPT4, using: inboundK1, counter: .init(offset: 0), nonce: nonce)
        let payloadCT = Array(source.readableBytesView.dropFirst(4).dropLast(16))
        let tag = Array(source.readableBytesView.suffix(16))

        // 1. Verify Poly1305 (one-time key from K_2, counter 0) over the concatenation
        //    lenCT‖payloadCT BEFORE decrypting. NIOSSH's Poly1305.update is single-shot — it
        //    pads the trailing partial block per call — so the MAC input must be one contiguous
        //    buffer, not two separate update() calls.
        var mac = Poly1305(key: try polyKey(inboundK2, nonce))
        mac.update(lenCT + payloadCT)
        guard Poly1305.constantTimeEqual(mac.finalize(), tag) else {
            throw NIOSSHError.invalidMACTag
        }

        // 2. Decrypt payload only after the tag verifies (K_2, counter 1).
        let payloadPT = try Insecure.ChaCha20CTR.encrypt(
            payloadCT, using: inboundK2, counter: .init(offset: 1), nonce: nonce)

        var plaintext = Data(payloadPT)
        try plaintext.removePaddingBytesChaCha()  // strip padding-length byte + padding
        source.clear()
        source.writeBytes(plaintext)
        return source.readSlice(length: plaintext.count)!
    }

    func encryptPacket(_ destination: inout ByteBuffer, sequenceNumber: UInt32) throws {
        let nonce = try Self.nonce(sequenceNumber)
        let all = Array(destination.readableBytesView)  // length(4)‖padlen‖payload‖padding
        let lenPT = Array(all.prefix(4))
        let payloadPT = Array(all.dropFirst(4))
        let lenCT = try Insecure.ChaCha20CTR.encrypt(
            lenPT, using: outboundK1, counter: .init(offset: 0), nonce: nonce)
        let payloadCT = try Insecure.ChaCha20CTR.encrypt(
            payloadPT, using: outboundK2, counter: .init(offset: 1), nonce: nonce)
        // Single-shot Poly1305 over the contiguous lenCT‖payloadCT (see decrypt path note).
        var mac = Poly1305(key: try polyKey(outboundK2, nonce))
        mac.update(lenCT + payloadCT)
        let tag = mac.finalize()
        // Overwrite the plaintext readable region IN PLACE with the equal-length ciphertext, then
        // append the tag. We must NOT clear()/rewrite from index 0: the serializer hands us a buffer
        // whose readable region is just this packet but which may hold earlier, not-yet-flushed
        // bytes before the reader index. clear() would discard those and desync the framing.
        let writeIndex = destination.readerIndex
        destination.setBytes(lenCT, at: writeIndex)
        destination.setBytes(payloadCT, at: writeIndex + lenCT.count)
        // writerIndex sits at the end of the readable region; append the tag there.
        destination.moveWriterIndex(to: writeIndex + lenCT.count + payloadCT.count)
        destination.writeBytes(tag)
    }
}

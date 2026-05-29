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

/// Base for `aes{128,192,256}-ctr` paired with `hmac-sha2-{256,512}[-etm@openssh.com]`.
///
/// Unlike AES-GCM and chacha20-poly1305 these are **non-AEAD** schemes: a CTR stream cipher is
/// combined with an explicitly negotiated HMAC, in one of two orderings:
///
///   - **Encrypt-and-MAC (E&M)** — the legacy SSH construction (`hmac-sha2-256` /
///     `hmac-sha2-512`). The whole packet `length ‖ padlen ‖ payload ‖ padding` is CTR-encrypted,
///     and the HMAC is taken over `seqnr ‖ plaintext`. The length field is encrypted, so
///     `lengthEncrypted == true`.
///   - **Encrypt-then-MAC (ETM)** — the `…-etm@openssh.com` variants. The 4-byte length is sent in
///     the clear; only `padlen ‖ payload ‖ padding` is CTR-encrypted; the HMAC is taken over
///     `seqnr ‖ length ‖ ciphertext`. The length field is cleartext, so `lengthEncrypted == false`.
///
/// The CTR counter is the 16-byte IV from key exchange, treated as a 128-bit big-endian integer
/// that advances by the number of cipher blocks consumed and persists across packets. On rekey the
/// counter resets to the new IV.
///
/// Subclasses supply the five class vars (`cipherName`, `macName`, `keySizes`, `isETM`,
/// `macIsSHA512`); all behaviour lives here.
internal class AESCTRTransportProtection {
    private var outboundKey: SymmetricKey
    private var inboundKey: SymmetricKey
    private var outboundMACKey: SymmetricKey
    private var inboundMACKey: SymmetricKey
    private var outboundCounter: [UInt8]  // running 16-byte big-endian counter
    private var inboundCounter: [UInt8]

    class var cipherName: String { fatalError("Must override cipher name") }
    class var macName: String? { fatalError("Must override MAC name") }
    class var keySizes: ExpectedKeySizes { fatalError("Must override key sizes") }
    class var isETM: Bool { fatalError("Must override isETM") }
    class var macIsSHA512: Bool { fatalError("Must override macIsSHA512") }

    required init(initialKeys: NIOSSHSessionKeys) throws {
        guard initialKeys.outboundEncryptionKey.bitCount == Self.keySizes.encryptionKeySize * 8,
            initialKeys.inboundEncryptionKey.bitCount == Self.keySizes.encryptionKeySize * 8
        else {
            throw NIOSSHError.invalidKeySize
        }
        self.outboundKey = initialKeys.outboundEncryptionKey
        self.inboundKey = initialKeys.inboundEncryptionKey
        self.outboundMACKey = initialKeys.outboundMACKey
        self.inboundMACKey = initialKeys.inboundMACKey
        self.outboundCounter = initialKeys.initialOutboundIV
        self.inboundCounter = initialKeys.initialInboundIV
        guard self.outboundCounter.count == 16, self.inboundCounter.count == 16 else {
            throw NIOSSHError.invalidNonceLength
        }
    }
}

extension AESCTRTransportProtection: NIOSSHTransportProtection {
    static var cipherBlockSize: Int { 16 }
    var macBytes: Int { Self.macIsSHA512 ? 64 : 32 }
    var lengthEncrypted: Bool { !Self.isETM }  // ETM => length on the wire is cleartext

    func updateKeys(_ newKeys: NIOSSHSessionKeys) throws {
        guard newKeys.outboundEncryptionKey.bitCount == Self.keySizes.encryptionKeySize * 8,
            newKeys.inboundEncryptionKey.bitCount == Self.keySizes.encryptionKeySize * 8
        else {
            throw NIOSSHError.invalidKeySize
        }
        guard newKeys.initialOutboundIV.count == 16, newKeys.initialInboundIV.count == 16 else {
            throw NIOSSHError.invalidNonceLength
        }
        self.outboundKey = newKeys.outboundEncryptionKey
        self.inboundKey = newKeys.inboundEncryptionKey
        self.outboundMACKey = newKeys.outboundMACKey
        self.inboundMACKey = newKeys.inboundMACKey
        self.outboundCounter = newKeys.initialOutboundIV  // reset counter from new IV on rekey
        self.inboundCounter = newKeys.initialInboundIV
    }

    /// CTR-transform `data` under `key` starting from `counter`, advancing the persistent counter
    /// by the number of 16-byte blocks consumed (rounded up). CTR is symmetric, so this serves both
    /// encryption and decryption.
    private func ctr(_ data: [UInt8], key: SymmetricKey, counter: inout [UInt8]) throws -> [UInt8] {
        let out = try AES._CTR.encrypt(data, using: key, nonce: .init(nonceBytes: counter))
        advance(&counter, blocks: (data.count + 15) / 16)  // cross-packet counter advance
        return Array(out)
    }

    /// Advance a 16-byte big-endian counter by `blocks`, with carry — matching BoringSSL's
    /// `AES_ctr128_encrypt`, which treats the full 16-byte IV as a 128-bit big-endian counter.
    private func advance(_ counter: inout [UInt8], blocks: Int) {
        var add = UInt64(blocks)
        var i = 15
        while add > 0 && i >= 0 {
            let sum = UInt64(counter[i]) + (add & 0xff)
            counter[i] = UInt8(sum & 0xff)
            add = (add >> 8) + (sum >> 8)
            i -= 1
        }
    }

    private func hmac(_ bytes: [UInt8], key: SymmetricKey) -> [UInt8] {
        Self.macIsSHA512
            ? Array(HMAC<SHA512>.authenticationCode(for: bytes, using: key))
            : Array(HMAC<SHA256>.authenticationCode(for: bytes, using: key))
    }

    private func hmacValid(_ tag: [UInt8], over bytes: [UInt8], key: SymmetricKey) -> Bool {
        Self.macIsSHA512
            ? HMAC<SHA512>.isValidAuthenticationCode(tag, authenticating: bytes, using: key)
            : HMAC<SHA256>.isValidAuthenticationCode(tag, authenticating: bytes, using: key)
    }

    func decryptFirstBlock(_ source: inout ByteBuffer, sequenceNumber _: UInt32) throws {
        // ETM: length is cleartext -> no-op (like GCM). E&M: CTR-decrypt the first 16 bytes against
        // a COPY of the running inbound counter to reveal the 4-byte length WITHOUT advancing the
        // persistent counter (the same bytes are decrypted again in decryptAndVerifyRemainingPacket,
        // where the persistent counter advances).
        guard !Self.isETM else { return }
        guard source.readableBytes >= 4 else { return }
        var c = self.inboundCounter
        let firstBlock = Array(source.readableBytesView.prefix(16))
        let pt = try AES._CTR.encrypt(firstBlock, using: self.inboundKey, nonce: .init(nonceBytes: c))
        advance(&c, blocks: 1)
        _ = c  // discard: the persistent counter advances in decryptAndVerifyRemainingPacket
        source.setBytes(Array(pt.prefix(4)), at: source.readerIndex)
    }

    func decryptAndVerifyRemainingPacket(_ source: inout ByteBuffer, sequenceNumber: UInt32) throws -> ByteBuffer {
        let seq = Self.seqBytes(sequenceNumber)

        if Self.isETM {
            // length(4, cleartext) ‖ ciphertext(padlen‖payload‖padding) ‖ MAC
            guard source.readableBytes >= 4 + self.macBytes else {
                throw NIOSSHError.invalidEncryptedPacketLength
            }
            let length = Array(source.readableBytesView.prefix(4))
            let ctLen = source.readableBytes - 4 - self.macBytes
            let ct = Array(source.readableBytesView.dropFirst(4).prefix(ctLen))
            let tag = Array(source.readableBytesView.suffix(self.macBytes))
            guard self.hmacValid(tag, over: seq + length + ct, key: self.inboundMACKey) else {
                throw NIOSSHError.invalidMACTag
            }
            let pt = try self.ctr(ct, key: self.inboundKey, counter: &self.inboundCounter)
            return try Self.finishPlaintext(&source, plaintext: pt)
        } else {
            // E&M: whole packet (length‖padlen‖payload‖padding) is CTR-encrypted; MAC over plaintext.
            guard source.readableBytes >= 4 + self.macBytes else {
                throw NIOSSHError.invalidEncryptedPacketLength
            }
            // `decryptFirstBlock` already revealed the 4-byte length and wrote the PLAINTEXT length
            // back into the buffer (without advancing the persistent counter). So the first 4 bytes
            // of `body` are plaintext; the rest is still ciphertext. CTR is symmetric, so we recover
            // the original ciphertext length bytes by re-encrypting the plaintext length against a
            // copy of the persistent counter (block 0), splice them back in, and then run a single
            // CTR pass over the full ciphertext body — which advances the persistent counter by the
            // correct number of blocks and keeps the keystream aligned across the whole packet.
            let lenPT = Array(source.readableBytesView.prefix(4))
            var counterCopy = self.inboundCounter
            let lenCT = try self.ctr(lenPT, key: self.inboundKey, counter: &counterCopy)  // copy advance discarded
            let body = lenCT + Array(source.readableBytesView.dropFirst(4).dropLast(self.macBytes))
            let tag = Array(source.readableBytesView.suffix(self.macBytes))
            let pt = try self.ctr(body, key: self.inboundKey, counter: &self.inboundCounter)  // incl. the 4 length bytes
            guard self.hmacValid(tag, over: seq + pt, key: self.inboundMACKey) else {
                throw NIOSSHError.invalidMACTag
            }
            return try Self.finishPlaintext(&source, plaintext: Array(pt.dropFirst(4)))  // drop length field
        }
    }

    func encryptPacket(_ destination: inout ByteBuffer, sequenceNumber: UInt32) throws {
        let seq = Self.seqBytes(sequenceNumber)
        let all = Array(destination.readableBytesView)  // length(4)‖padlen‖payload‖padding
        // Overwrite the plaintext readable region IN PLACE with the equal-length ciphertext, then
        // append the tag. We must NOT clear()/rewrite from index 0: the serializer hands us a buffer
        // whose readable region is just this packet but which may hold earlier, not-yet-flushed
        // bytes before the reader index. clear() would discard those and desync the framing.
        let writeIndex = destination.readerIndex
        if Self.isETM {
            let length = Array(all.prefix(4))
            let ct = try self.ctr(Array(all.dropFirst(4)), key: self.outboundKey, counter: &self.outboundCounter)
            let tag = self.hmac(seq + length + ct, key: self.outboundMACKey)
            destination.setBytes(length, at: writeIndex)
            destination.setBytes(ct, at: writeIndex + length.count)
            destination.moveWriterIndex(to: writeIndex + length.count + ct.count)
            destination.writeBytes(tag)
        } else {
            let tag = self.hmac(seq + all, key: self.outboundMACKey)  // MAC over plaintext, incl. length
            let ct = try self.ctr(all, key: self.outboundKey, counter: &self.outboundCounter)
            destination.setBytes(ct, at: writeIndex)
            destination.moveWriterIndex(to: writeIndex + ct.count)
            destination.writeBytes(tag)
        }
    }

    /// The sequence number as a big-endian 4-byte array, prefixed to the MAC input per RFC 4253 §6.4.
    private static func seqBytes(_ sequenceNumber: UInt32) -> [UInt8] {
        [
            UInt8((sequenceNumber >> 24) & 0xff),
            UInt8((sequenceNumber >> 16) & 0xff),
            UInt8((sequenceNumber >> 8) & 0xff),
            UInt8(sequenceNumber & 0xff),
        ]
    }

    /// Strip the padding-length byte and trailing padding, write the payload back into `source`, and
    /// return a slice of it (reusing the buffer's storage where possible).
    private static func finishPlaintext(_ source: inout ByteBuffer, plaintext: [UInt8]) throws -> ByteBuffer {
        var data = Data(plaintext)
        try data.removePaddingBytesChaCha()  // shared padlen+padding strip helper (PaddingStripping.swift)
        source.clear()
        source.writeBytes(data)
        return source.readSlice(length: data.count)!
    }
}

// MARK: - 12 cross-product final subclasses
//
// aes{128,192,256}-ctr × hmac-sha2-{256,512} × {ETM, E&M}. Each overrides only the five class vars.

final class AES128CTR_HMACSHA256ETM: AESCTRTransportProtection, _NIOSSHSendableMetatype {
    override static var cipherName: String { "aes128-ctr" }
    override static var macName: String? { "hmac-sha2-256-etm@openssh.com" }
    override static var keySizes: ExpectedKeySizes { .init(ivSize: 16, encryptionKeySize: 16, macKeySize: 32) }
    override static var isETM: Bool { true }
    override static var macIsSHA512: Bool { false }
}

final class AES128CTR_HMACSHA512ETM: AESCTRTransportProtection, _NIOSSHSendableMetatype {
    override static var cipherName: String { "aes128-ctr" }
    override static var macName: String? { "hmac-sha2-512-etm@openssh.com" }
    override static var keySizes: ExpectedKeySizes { .init(ivSize: 16, encryptionKeySize: 16, macKeySize: 64) }
    override static var isETM: Bool { true }
    override static var macIsSHA512: Bool { true }
}

final class AES128CTR_HMACSHA256: AESCTRTransportProtection, _NIOSSHSendableMetatype {
    override static var cipherName: String { "aes128-ctr" }
    override static var macName: String? { "hmac-sha2-256" }
    override static var keySizes: ExpectedKeySizes { .init(ivSize: 16, encryptionKeySize: 16, macKeySize: 32) }
    override static var isETM: Bool { false }
    override static var macIsSHA512: Bool { false }
}

final class AES128CTR_HMACSHA512: AESCTRTransportProtection, _NIOSSHSendableMetatype {
    override static var cipherName: String { "aes128-ctr" }
    override static var macName: String? { "hmac-sha2-512" }
    override static var keySizes: ExpectedKeySizes { .init(ivSize: 16, encryptionKeySize: 16, macKeySize: 64) }
    override static var isETM: Bool { false }
    override static var macIsSHA512: Bool { true }
}

final class AES192CTR_HMACSHA256ETM: AESCTRTransportProtection, _NIOSSHSendableMetatype {
    override static var cipherName: String { "aes192-ctr" }
    override static var macName: String? { "hmac-sha2-256-etm@openssh.com" }
    override static var keySizes: ExpectedKeySizes { .init(ivSize: 16, encryptionKeySize: 24, macKeySize: 32) }
    override static var isETM: Bool { true }
    override static var macIsSHA512: Bool { false }
}

final class AES192CTR_HMACSHA512ETM: AESCTRTransportProtection, _NIOSSHSendableMetatype {
    override static var cipherName: String { "aes192-ctr" }
    override static var macName: String? { "hmac-sha2-512-etm@openssh.com" }
    override static var keySizes: ExpectedKeySizes { .init(ivSize: 16, encryptionKeySize: 24, macKeySize: 64) }
    override static var isETM: Bool { true }
    override static var macIsSHA512: Bool { true }
}

final class AES192CTR_HMACSHA256: AESCTRTransportProtection, _NIOSSHSendableMetatype {
    override static var cipherName: String { "aes192-ctr" }
    override static var macName: String? { "hmac-sha2-256" }
    override static var keySizes: ExpectedKeySizes { .init(ivSize: 16, encryptionKeySize: 24, macKeySize: 32) }
    override static var isETM: Bool { false }
    override static var macIsSHA512: Bool { false }
}

final class AES192CTR_HMACSHA512: AESCTRTransportProtection, _NIOSSHSendableMetatype {
    override static var cipherName: String { "aes192-ctr" }
    override static var macName: String? { "hmac-sha2-512" }
    override static var keySizes: ExpectedKeySizes { .init(ivSize: 16, encryptionKeySize: 24, macKeySize: 64) }
    override static var isETM: Bool { false }
    override static var macIsSHA512: Bool { true }
}

final class AES256CTR_HMACSHA256ETM: AESCTRTransportProtection, _NIOSSHSendableMetatype {
    override static var cipherName: String { "aes256-ctr" }
    override static var macName: String? { "hmac-sha2-256-etm@openssh.com" }
    override static var keySizes: ExpectedKeySizes { .init(ivSize: 16, encryptionKeySize: 32, macKeySize: 32) }
    override static var isETM: Bool { true }
    override static var macIsSHA512: Bool { false }
}

final class AES256CTR_HMACSHA512ETM: AESCTRTransportProtection, _NIOSSHSendableMetatype {
    override static var cipherName: String { "aes256-ctr" }
    override static var macName: String? { "hmac-sha2-512-etm@openssh.com" }
    override static var keySizes: ExpectedKeySizes { .init(ivSize: 16, encryptionKeySize: 32, macKeySize: 64) }
    override static var isETM: Bool { true }
    override static var macIsSHA512: Bool { true }
}

final class AES256CTR_HMACSHA256: AESCTRTransportProtection, _NIOSSHSendableMetatype {
    override static var cipherName: String { "aes256-ctr" }
    override static var macName: String? { "hmac-sha2-256" }
    override static var keySizes: ExpectedKeySizes { .init(ivSize: 16, encryptionKeySize: 32, macKeySize: 32) }
    override static var isETM: Bool { false }
    override static var macIsSHA512: Bool { false }
}

final class AES256CTR_HMACSHA512: AESCTRTransportProtection, _NIOSSHSendableMetatype {
    override static var cipherName: String { "aes256-ctr" }
    override static var macName: String? { "hmac-sha2-512" }
    override static var keySizes: ExpectedKeySizes { .init(ivSize: 16, encryptionKeySize: 32, macKeySize: 64) }
    override static var isETM: Bool { false }
    override static var macIsSHA512: Bool { true }
}

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
import Foundation
import NIOCore
import NIOFoundationCompat

/// A base class for the AES GCM transport protection implementations.
///
/// All four AES GCM transport protection implementations are almost identical: they differ only in their
/// expected key sizes and whether or not they negotiate an explicit MAC. As this is simply static data, we
/// can use a single base class to implement the logic and have the subclasses provide the static data we need.
internal class AESGCMTransportProtection {
    private var outboundEncryptionKey: SymmetricKey
    private var inboundEncryptionKey: SymmetricKey
    private var outboundNonce: SSHAESGCMNonce
    private var inboundNonce: SSHAESGCMNonce

    class var cipherName: String {
        fatalError("Must override cipher name")
    }

    class var macName: String? {
        fatalError("Must override MAC name")
    }

    class var keySizes: ExpectedKeySizes {
        fatalError("Must override key size")
    }

    required init(initialKeys: NIOSSHSessionKeys) throws {
        guard initialKeys.outboundEncryptionKey.bitCount == Self.keySizes.encryptionKeySize * 8,
            initialKeys.inboundEncryptionKey.bitCount == Self.keySizes.encryptionKeySize * 8
        else {
            throw NIOSSHError.invalidKeySize
        }

        self.outboundEncryptionKey = initialKeys.outboundEncryptionKey
        self.inboundEncryptionKey = initialKeys.inboundEncryptionKey
        self.outboundNonce = try SSHAESGCMNonce(keyExchangeResult: initialKeys.initialOutboundIV)
        self.inboundNonce = try SSHAESGCMNonce(keyExchangeResult: initialKeys.initialInboundIV)
    }
}

extension AESGCMTransportProtection: NIOSSHTransportProtection {
    static var cipherBlockSize: Int {
        16
    }

    var macBytes: Int {
        16
    }

    var lengthEncrypted: Bool {
        false
    }

    // AEAD: the length is cleartext additional authenticated data (aadlen == 4), excluded from the
    // block-padding modulus.
    var lengthIncludedInPadding: Bool {
        false
    }

    func updateKeys(_ newKeys: NIOSSHSessionKeys) throws {
        guard newKeys.outboundEncryptionKey.bitCount == Self.keySizes.encryptionKeySize * 8,
            newKeys.inboundEncryptionKey.bitCount == Self.keySizes.encryptionKeySize * 8
        else {
            throw NIOSSHError.invalidKeySize
        }

        self.outboundEncryptionKey = newKeys.outboundEncryptionKey
        self.inboundEncryptionKey = newKeys.inboundEncryptionKey
        self.outboundNonce = try SSHAESGCMNonce(keyExchangeResult: newKeys.initialOutboundIV)
        self.inboundNonce = try SSHAESGCMNonce(keyExchangeResult: newKeys.initialInboundIV)
    }

    func decryptFirstBlock(_: inout ByteBuffer, sequenceNumber _: UInt32) throws {
        // For us, decrypting the first block is very easy: do nothing. The length bytes are already
        // unencrypted!
    }

    func decryptAndVerifyRemainingPacket(_ source: inout ByteBuffer, sequenceNumber _: UInt32) throws -> ByteBuffer {
        // The first 4 bytes are the length. The last 16 are the tag. Everything else is ciphertext. We expect
        // that the ciphertext is a clean multiple of the block size, and to be non-zero.
        let ciphertextLength = source.readableBytes - Self.packetLengthBytes - Self.tagBytes
        guard ciphertextLength > 0, ciphertextLength % Self.cipherBlockSize == 0 else {
            // The only way this fails is if the payload doesn't match this encryption scheme.
            throw NIOSSHError.invalidEncryptedPacketLength
        }

        let nonce = try AES.GCM.Nonce(data: self.inboundNonce)
        if #available(macOS 27, iOS 27, tvOS 27, watchOS 27, visionOS 27, *) {
            try Self.openInPlace(&source, using: self.inboundEncryptionKey, nonce: nonce)
        } else {
            try Self.openCopying(&source, using: self.inboundEncryptionKey, nonce: nonce)
        }

        // Don't forget to increment the inbound nonce.
        self.inboundNonce.increment()

        return try Self.consumeOpenedPacket(&source, plaintextLength: ciphertextLength)
    }

    func encryptPacket(_ destination: inout ByteBuffer, sequenceNumber: UInt32) throws {
        let nonce = try AES.GCM.Nonce(data: self.outboundNonce)
        if #available(macOS 27, iOS 27, tvOS 27, watchOS 27, visionOS 27, *) {
            try Self.sealInPlace(&destination, using: self.outboundEncryptionKey, nonce: nonce)
        } else {
            try Self.sealCopying(&destination, using: self.outboundEncryptionKey, nonce: nonce)
        }

        // Now we increment the Nonce for the next use, and then we're done!
        self.outboundNonce.increment()
    }
}

// The AEAD step of the transport, in two interchangeable implementations. Both take a packet whose readable bytes
// are exactly `[length (4)][body][tag (16)]` (open) or `[length (4)][body]` (seal), use the cleartext length as
// the additional authenticated data, and leave the reader and writer indices as the framing above expects. The
// in-place pair encrypts and decrypts the body inside the buffer's own storage (CryptoKit on OS 27, swift-crypto
// elsewhere); the copying pair is the OS 26 road and stays directly callable so tests can hold the two equal.
extension AESGCMTransportProtection {
    static var packetLengthBytes: Int { MemoryLayout<UInt32>.size }

    static var tagBytes: Int { 16 }

    /// Decrypts and verifies the body of `packet` in place, leaving the plaintext where the ciphertext was.
    @available(macOS 27, iOS 27, tvOS 27, watchOS 27, visionOS 27, *)
    static func openInPlace(_ packet: inout ByteBuffer, using key: SymmetricKey, nonce: AES.GCM.Nonce) throws {
        let lengthBytes = Self.packetLengthBytes
        let tagBytes = Self.tagBytes
        try packet.withUnsafeMutableReadableBytes { bytes in
            let bodyEnd = bytes.count - tagBytes
            let lengthField = UnsafeRawBufferPointer(rebasing: bytes[..<lengthBytes])
            let tagField = UnsafeRawBufferPointer(rebasing: bytes[bodyEnd...])
            let bodyField = UnsafeMutableRawBufferPointer(rebasing: bytes[lengthBytes..<bodyEnd])
            var body = bodyField.mutableBytes
            try AES.GCM.open(
                inPlace: &body,
                using: key,
                nonce: nonce,
                authenticating: lengthField.bytes,
                tag: tagField.bytes
            )
        }
    }

    /// The OS 26 road of ``openInPlace(_:using:nonce:)``: decrypts into a fresh allocation and writes the
    /// plaintext back over the ciphertext.
    static func openCopying(_ packet: inout ByteBuffer, using key: SymmetricKey, nonce: AES.GCM.Nonce) throws {
        let bodyIndex = packet.readerIndex + Self.packetLengthBytes
        let bodyLength = packet.readableBytes - Self.packetLengthBytes - Self.tagBytes
        let plaintext: Data
        // Establish a nested scope here to avoid the byte buffer views causing an accidental CoW.
        do {
            let lengthView = packet.viewBytes(at: packet.readerIndex, length: Self.packetLengthBytes)!
            let ciphertextView = packet.viewBytes(at: bodyIndex, length: bodyLength)!
            let tagView = packet.viewBytes(at: bodyIndex + bodyLength, length: Self.tagBytes)!
            let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertextView, tag: tagView)
            plaintext = try AES.GCM.open(sealedBox, using: key, authenticating: lengthView)
        }
        guard plaintext.count == bodyLength else {
            throw NIOSSHError.invalidDecryptedPlaintextLength
        }
        packet.setContiguousBytes(plaintext, at: bodyIndex)
    }

    /// Encrypts the body of `packet` in place and appends the tag.
    @available(macOS 27, iOS 27, tvOS 27, watchOS 27, visionOS 27, *)
    static func sealInPlace(_ packet: inout ByteBuffer, using key: SymmetricKey, nonce: AES.GCM.Nonce) throws {
        let lengthBytes = Self.packetLengthBytes
        let tagBytes = Self.tagBytes
        packet.writeRepeatingByte(0, count: tagBytes)
        let tagLength = try packet.withUnsafeMutableReadableBytes { bytes in
            let bodyEnd = bytes.count - tagBytes
            let lengthField = UnsafeRawBufferPointer(rebasing: bytes[..<lengthBytes])
            let bodyField = UnsafeMutableRawBufferPointer(rebasing: bytes[lengthBytes..<bodyEnd])
            let tagField = UnsafeMutableRawBufferPointer(rebasing: bytes[bodyEnd...])
            var body = bodyField.mutableBytes
            var tag = OutputRawSpan(buffer: tagField, initializedCount: 0)
            try AES.GCM.seal(
                inPlace: &body,
                using: key,
                nonce: nonce,
                authenticating: lengthField.bytes,
                tag: &tag
            )
            return tag.finalize(for: tagField)
        }
        precondition(tagLength == tagBytes, "Unexpected short tag")
    }

    /// The OS 26 road of ``sealInPlace(_:using:nonce:)``: encrypts into a fresh allocation, writes the
    /// ciphertext back over the plaintext and appends the tag.
    static func sealCopying(_ packet: inout ByteBuffer, using key: SymmetricKey, nonce: AES.GCM.Nonce) throws {
        let bodyIndex = packet.readerIndex + Self.packetLengthBytes
        let bodyLength = packet.readableBytes - Self.packetLengthBytes
        // We know these views will be valid, so we forcibly unwrap them: if they're invalid, our math was wrong
        // and we cannot recover.
        let sealedBox = try AES.GCM.seal(
            packet.viewBytes(at: bodyIndex, length: bodyLength)!,
            using: key,
            nonce: nonce,
            authenticating: packet.viewBytes(at: packet.readerIndex, length: Self.packetLengthBytes)!
        )
        assert(sealedBox.ciphertext.count == bodyLength)
        packet.setContiguousBytes(sealedBox.ciphertext, at: bodyIndex)
        let tagLength = packet.writeContiguousBytes(sealedBox.tag)
        precondition(tagLength == Self.tagBytes, "Unexpected short tag")
    }

    /// Strips the length, padding-length byte, padding and tag from an opened packet, returning the payload and
    /// leaving `packet` fully consumed.
    static func consumeOpenedPacket(_ packet: inout ByteBuffer, plaintextLength: Int) throws -> ByteBuffer {
        packet.moveReaderIndex(forwardBy: Self.packetLengthBytes)
        guard let paddingLength = packet.readInteger(as: UInt8.self), paddingLength >= 4 else {
            throw NIOSSHError.insufficientPadding
        }
        // If the padding walks off the front of the body there is too much padding for the available data.
        let payloadLength = plaintextLength - 1 - Int(paddingLength)
        guard payloadLength >= 0 else {
            throw NIOSSHError.excessPadding
        }
        // This slice read must succeed: the body holds at least that many bytes.
        let payload = packet.readSlice(length: payloadLength)!
        packet.moveReaderIndex(to: packet.writerIndex)
        return payload
    }
}

/// An implementation of AES128 GCM in OpenSSH mode.
///
/// The OpenSSH mode of AES128 GCM differs from the RFC 5647 version by not offering a MAC
/// algorithm, and instead by ignoring the result of the MAC negotiation.
///
/// This algorithm does not encrypt the length field, instead encoding it as associated data.
final class AES128GCMOpenSSHTransportProtection: AESGCMTransportProtection, _NIOSSHSendableMetatype {
    override static var cipherName: String {
        "aes128-gcm@openssh.com"
    }

    override static var macName: String? {
        nil
    }

    override static var keySizes: ExpectedKeySizes {
        .init(ivSize: 12, encryptionKeySize: 16, macKeySize: 16)
    }
}

/// An implementation of AES256 GCM in OpenSSH mode.
///
/// The OpenSSH mode of AES256 GCM differs from the RFC 5647 version by not offering a MAC
/// algorithm, and instead by ignoring the result of the MAC negotiation.
///
/// This algorithm does not encrypt the length field, instead encoding it as associated data.
final class AES256GCMOpenSSHTransportProtection: AESGCMTransportProtection, _NIOSSHSendableMetatype {
    override static var cipherName: String {
        "aes256-gcm@openssh.com"
    }

    override static var macName: String? {
        nil
    }

    override static var keySizes: ExpectedKeySizes {
        .init(ivSize: 12, encryptionKeySize: 32, macKeySize: 16)
    }
}

// MARK: - SSHAESGCMNonce

/// A representation of the AES GCM Nonce as a weird hybrid integer for SSH.
///
/// SSH has an awkward requirement that we be able to perform a certain amount of integer math on an
/// AES GCM Nonce. Specifically, we have this, from RFC 5647 § 7.1:
///
/// > With AES-GCM, the 12-octet IV is broken into two fields: a 4-octet
/// > fixed field and an 8-octet invocation counter field.  The invocation
/// > field is treated as a 64-bit integer and is incremented after each
/// > invocation of AES-GCM to process a binary packet.
///
/// Internally we have a few requirements: we'd like to be able to store and manipulate these nonces
/// without heap allocations, and we'd like to be able to quickly create CryptoKit `AES.GCM.Nonce` objects.
/// That requires a slightly custom data structure. Specifically, this custom data structure needs to be able
/// to rapidly vend an interior pointer for the use of the DataProtocol constructor that CryptoKit wants.
///
/// Thus, it must conform to DataProtocol, ContiguousBytes, and therefore also RandomAccessCollection. This is a
/// thoroughly awkward data structure, but we can make it work.
struct SSHAESGCMNonce {
    /// We store the nonce as a tuple of 64-bit integers. This conveniently allows us to access the nonce
    /// via a pointer, which is useful for the DataProtocol conformance we need to easily create AES.GCM.Nonce
    /// types.
    ///
    /// The observant may notice that an AES GCM Nonce is 12 bytes long, but we have 16 bytes here. We avoid
    /// using the leftmost 4 bytes in memory: they should always be zeros.
    private var baseNonceRepresentation: (UInt64, UInt64) = (0, 0)

    init(keyExchangeResult: [UInt8]) throws {
        guard keyExchangeResult.count == 12 else {
            throw NIOSSHError.invalidNonceLength
        }

        withUnsafeMutableBytes(of: &self.baseNonceRepresentation) { reprPointer in
            /// The top 4 bytes are irrelevant.
            let reprPointer = UnsafeMutableRawBufferPointer(rebasing: reprPointer[4...])
            precondition(reprPointer.count == 12)
            reprPointer.copyBytes(from: keyExchangeResult)
        }
    }
}

extension SSHAESGCMNonce {
    mutating func increment() {
        // Here we implement the following requirement from RFC 5647:
        //
        // > With AES-GCM, the 12-octet IV is broken into two fields: a 4-octet
        // > fixed field and an 8-octet invocation counter field.  The invocation
        // > field is treated as a 64-bit integer and is incremented after each
        // > invocation of AES-GCM to process a binary packet.
        //
        // Note that we have to do this in network byte order. Thus, the 8 octet invocation
        // counter field is currently sitting in the second UInt64 in the tuple, but note that
        // it is stored there in *network byte order*. To make the addition work, we need to do
        // some endianness swaps.
        //
        // One final note: overflow is expected and allowed in this addition.
        self.baseNonceRepresentation.1 = (UInt64(bigEndian: self.baseNonceRepresentation.1) &+ 1).bigEndian
    }
}

// MARK: RandomAccessCollection conformace

extension SSHAESGCMNonce: RandomAccessCollection {
    struct Index: Strideable, Comparable, Hashable {
        fileprivate var offset: Int

        init(fromOffset offset: Int) {
            self.offset = offset
        }

        func advanced(by n: Int) -> SSHAESGCMNonce.Index {
            Index(fromOffset: self.offset + n)
        }

        func distance(to other: SSHAESGCMNonce.Index) -> Int {
            other.offset - self.offset
        }

        static func < (lhs: SSHAESGCMNonce.Index, rhs: SSHAESGCMNonce.Index) -> Bool {
            lhs.offset < rhs.offset
        }
    }

    var startIndex: SSHAESGCMNonce.Index {
        Index(fromOffset: 4)
    }

    var endIndex: SSHAESGCMNonce.Index {
        Index(fromOffset: 16)
    }

    subscript(position: SSHAESGCMNonce.Index) -> UInt8 {
        precondition(
            position.offset >= 4 && position.offset < MemoryLayout.size(ofValue: self.baseNonceRepresentation),
            "Invalid index!"
        )

        return Swift.withUnsafeBytes(of: self.baseNonceRepresentation) { reprPointer in
            reprPointer[position.offset]
        }
    }

    func index(after i: SSHAESGCMNonce.Index) -> SSHAESGCMNonce.Index {
        Index(fromOffset: i.offset + 1)
    }
}

// MARK: ContiguousBytes conformance

extension SSHAESGCMNonce: ContiguousBytes {
    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try Swift.withUnsafeBytes(of: self.baseNonceRepresentation) { reprPointer in
            let reprPointer = UnsafeRawBufferPointer(rebasing: reprPointer[4...])
            return try body(reprPointer)
        }
    }
}

// MARK: DataProtocol conformance

extension SSHAESGCMNonce: DataProtocol {
    var regions: CollectionOfOne<SSHAESGCMNonce> {
        .init(self)
    }
}

extension AES.GCM.SealedBox {
    fileprivate init(nonce: AES.GCM.Nonce, ciphertext: ByteBufferView, tag: ByteBufferView) throws {
        // As a workaround for a Swift Crypto inefficiency, we create the combined representation
        // directly.
        var combined: [UInt8] = []
        nonce.withUnsafeBytes { nonceBytes in
            combined.reserveCapacity(nonceBytes.count + ciphertext.count + tag.count)
            combined.append(contentsOf: nonceBytes)
        }
        combined.append(contentsOf: ciphertext)
        combined.append(contentsOf: tag)

        try self.init(combined: combined)
    }
}

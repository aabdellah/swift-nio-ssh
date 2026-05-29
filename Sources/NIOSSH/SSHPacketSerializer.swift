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

import NIOCore

struct SSHPacketSerializer {
    enum State {
        case initialized
        case cleartext
        case encrypted(NIOSSHTransportProtection)
    }

    private var state: State = .initialized
    private(set) var sequenceNumber: UInt32 = 0

    /// Resets the outbound sequence number to 0.
    /// Used by strict KEX (Terrapin CVE-2023-48795 mitigation) after sending SSH_MSG_NEWKEYS.
    mutating func resetSequenceNumber() {
        self.sequenceNumber = 0
    }

    /// Encryption schemes can be added to a packet serializer whenever encryption is negotiated.
    mutating func addEncryption(_ protection: NIOSSHTransportProtection) {
        switch self.state {
        case .cleartext:
            self.state = .encrypted(protection)
        case .encrypted:
            self.state = .encrypted(protection)
        case .initialized:
            preconditionFailure("Adding encryption in invalid state: \(self.state)")
        }
    }

    mutating func serialize(message: SSHMessage, to buffer: inout ByteBuffer) throws {
        switch self.state {
        case .initialized:
            switch message {
            case .version:
                buffer.writeSSHMessage(message)
                self.state = .cleartext
            default:
                preconditionFailure("only .version message is allowed at this point")
            }
        case .cleartext:
            // Pre-encryption framing has no cipher/MAC installed (OpenSSH: aadlen == 0), so the
            // length field counts toward the block-8 padding modulus.
            buffer.writeSSHPacket(message: message, lengthIncludedInPadding: true, blockSize: 8)
            self.sequenceNumber &+= 1
        case .encrypted(let protection):
            let index = buffer.readerIndex
            buffer.moveReaderIndex(to: buffer.writerIndex)
            buffer.writeSSHPacket(
                message: message,
                lengthIncludedInPadding: protection.lengthIncludedInPadding,
                blockSize: protection.cipherBlockSize
            )
            try protection.encryptPacket(&buffer, sequenceNumber: self.sequenceNumber)
            buffer.moveReaderIndex(to: index)
            self.sequenceNumber &+= 1
        }
    }
}

extension ByteBuffer {
    mutating func writeSSHPacket(message: SSHMessage, lengthIncludedInPadding: Bool, blockSize: Int) {
        let index = self.writerIndex

        /// Each packet is in the following format:
        ///
        ///   uint32        packet_length
        ///   byte           padding_length
        ///   byte[n1]  payload; n1 = packet_length - padding_length - 1
        ///   byte[n2]  random padding; n2 = padding_length
        ///   byte[m]   mac (Message Authentication Code - MAC); m = mac_length

        /// payload
        self.writeMultipleIntegers(UInt32(0), UInt8(0))
        let messageLength = self.writeSSHMessage(message)

        // RFC 4253 §6 / OpenSSH `packet.c`: the padding modulus is taken over
        // `packet_length ‖ padding_length ‖ payload ‖ padding`, except that AEAD and ETM schemes
        // treat the 4-byte packet_length field as additional authenticated data and EXCLUDE it
        // (`len -= aadlen` with aadlen == 4). So the base we pad is:
        //   - length INCLUDED (E&M / cleartext, aadlen == 0): 4 (length) + 1 (padlen) + payload
        //   - length EXCLUDED (AEAD / ETM,      aadlen == 4):     1 (padlen) + payload
        let payloadLength = lengthIncludedInPadding ? messageLength + 5 : messageLength + 1

        /// RFC 4253 § 6:
        /// random padding
        ///   Arbitrary-length padding, such that the total length of (packet_length || padding_length || payload || random padding)
        ///   is a multiple of the cipher block size or 8, whichever is larger.  There MUST be at least four bytes of padding.  The
        ///   padding SHOULD consist of random bytes.  The maximum amount of padding is 255 bytes.
        var paddingLength = blockSize - (payloadLength % blockSize)
        if paddingLength < 4 {
            paddingLength += blockSize
        }

        /// packet_length
        ///   The length of the packet in bytes, not including 'mac' or the 'packet_length' field itself.
        let packetLength = 1 + messageLength + paddingLength
        self.setInteger(UInt32(packetLength), at: index)
        /// padding_length
        self.setInteger(UInt8(paddingLength), at: index + 4)
        /// random padding
        self.writeSSHPaddingBytes(count: paddingLength)
    }
}

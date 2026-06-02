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
import NIOFoundationCompat

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// Hybrid post-quantum key exchange `mlkem768x25519-sha256`.
///
/// Composes ML-KEM-768 (FIPS 203 module-lattice KEM) with X25519 ECDH, per
/// draft-ietf-sshm-mlkem-hybrid-kex. The client sends `C_INIT = ek ‖ x25519_pub`; the server
/// replies `S_REPLY = ciphertext ‖ x25519_pub`; the shared secret is
/// `K = SHA256(K_MLKEM ‖ K_X25519)`. K is encoded as an SSH *string* (not an mpint) in both the
/// exchange hash and the RFC 4253 §7.2 key derivation.
///
/// This type is deliberately self-contained: it does NOT reuse the generic
/// `EllipticCurveKeyExchange` machinery, so the shipped classical `SharedSecret`/mpint path stays
/// untouched. The exchange-hash and KDF here are a small SHA-256-specialised copy.
///
/// - Note: `MLKEM768` from the system CryptoKit (re-exported by swift-crypto on Apple platforms)
///   is gated at macOS 26.0 / iOS 26.0 / watchOS 26.0 / tvOS 26.0 / visionOS 26.0, so this type
///   carries that availability floor even though the package itself targets macOS 10.15.
@available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
struct MLKEM768X25519KeyExchange: EllipticCurveKeyExchangeProtocol {
    // FIPS 203 / RFC 7748 sizes.
    private static let mlkemEncapsulationKeyBytes = 1184
    private static let mlkemCiphertextBytes = 1088
    private static let x25519PublicKeyBytes = 32
    private static let cInitBytes = mlkemEncapsulationKeyBytes + x25519PublicKeyBytes  // 1216
    private static let sReplyBytes = mlkemCiphertextBytes + x25519PublicKeyBytes       // 1120

    static var keyExchangeAlgorithmNames: [Substring] { ["mlkem768x25519-sha256"] }

    private var ourRole: SSHConnectionRole
    private var previousSessionIdentifier: ByteBuffer?
    private var x25519PrivateKey: Curve25519.KeyAgreement.PrivateKey
    /// Client-only: retained so we can decapsulate the server's ciphertext. `nil` on the server.
    private var mlkemPrivateKey: MLKEM768.PrivateKey?

    init(ourRole: SSHConnectionRole, previousSessionIdentifier: ByteBuffer?) {
        self.ourRole = ourRole
        self.previousSessionIdentifier = previousSessionIdentifier
        self.x25519PrivateKey = Curve25519.KeyAgreement.PrivateKey()
        // ML-KEM key generation can only fail on catastrophic RNG failure (fatal regardless). The
        // protocol's keygen entry points are non-throwing, matching how the EC curves treat this.
        self.mlkemPrivateKey = ourRole.isClient ? try! MLKEM768.PrivateKey() : nil
    }
}

@available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
extension MLKEM768X25519KeyExchange {
    func initiateKeyExchangeClientSide(allocator: ByteBufferAllocator) -> SSHMessage.KeyExchangeECDHInitMessage {
        precondition(self.ourRole.isClient, "Only clients may initiate the client side key exchange!")
        var buffer = allocator.buffer(capacity: Self.cInitBytes)
        buffer.writeContiguousBytes(self.mlkemPrivateKey!.publicKey.rawRepresentation)  // ek (1184)
        buffer.writeContiguousBytes(self.x25519PrivateKey.publicKey.rawRepresentation)  // x25519 (32)
        return .init(publicKey: buffer)
    }

    mutating func completeKeyExchangeServerSide(
        clientKeyExchangeMessage message: SSHMessage.KeyExchangeECDHInitMessage,
        serverHostKey: NIOSSHPrivateKey,
        initialExchangeBytes: inout ByteBuffer,
        allocator: ByteBufferAllocator,
        expectedKeySizes: ExpectedKeySizes
    ) throws -> (KeyExchangeResult, SSHMessage.KeyExchangeECDHReplyMessage) {
        precondition(self.ourRole.isServer, "Only servers may receive a client key exchange packet!")

        // Parse C_INIT = ek(1184) ‖ x25519_client(32).
        var cInit = message.publicKey
        guard cInit.readableBytes == Self.cInitBytes,
            let ekBytes = cInit.readBytes(length: Self.mlkemEncapsulationKeyBytes),
            let clientX25519Bytes = cInit.readBytes(length: Self.x25519PublicKeyBytes)
        else { throw NIOSSHError.invalidKeySize }

        // ML-KEM encapsulate against the client's ek → (ciphertext, K_PQ).
        let encapsulation = try MLKEM768.PublicKey(rawRepresentation: ekBytes).encapsulate()
        let ciphertext = Array(encapsulation.encapsulated)  // 1088
        let kPQ = encapsulation.sharedSecret                // SymmetricKey (32)

        // X25519 agreement.
        let clientX25519 = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: clientX25519Bytes)
        let kCL = try self.x25519SharedSecretBytes(with: clientX25519)

        // S_REPLY = ciphertext ‖ x25519_server.
        let serverX25519Bytes = Array(self.x25519PrivateKey.publicKey.rawRepresentation)
        var sReplyBuffer = allocator.buffer(capacity: Self.sReplyBytes)
        sReplyBuffer.writeBytes(ciphertext)
        sReplyBuffer.writeBytes(serverX25519Bytes)

        let kString = Self.combinedSecretAsSSHString(kPQ: kPQ, kCL: kCL)
        let (exchangeHash, sessionID, keys) = self.finalize(
            cInit: ekBytes + clientX25519Bytes,
            sReply: ciphertext + serverX25519Bytes,
            serverHostKey: serverHostKey.publicKey,
            kString: kString,
            initialExchangeBytes: &initialExchangeBytes,
            allocator: allocator,
            expectedKeySizes: expectedKeySizes
        )

        let signature = try serverHostKey.sign(digest: exchangeHash)
        let reply = SSHMessage.KeyExchangeECDHReplyMessage(
            hostKey: serverHostKey.publicKey,
            publicKey: sReplyBuffer,
            signature: signature
        )
        return (KeyExchangeResult(sessionID: sessionID, keys: keys), reply)
    }

    mutating func receiveServerKeyExchangePayload(
        serverKeyExchangeMessage message: SSHMessage.KeyExchangeECDHReplyMessage,
        initialExchangeBytes: inout ByteBuffer,
        allocator: ByteBufferAllocator,
        expectedKeySizes: ExpectedKeySizes
    ) throws -> KeyExchangeResult {
        precondition(self.ourRole.isClient, "Only clients may receive a server key exchange packet!")

        // Parse S_REPLY = ct(1088) ‖ x25519_server(32).
        var sReply = message.publicKey
        guard sReply.readableBytes == Self.sReplyBytes,
            let ctBytes = sReply.readBytes(length: Self.mlkemCiphertextBytes),
            let serverX25519Bytes = sReply.readBytes(length: Self.x25519PublicKeyBytes)
        else { throw NIOSSHError.invalidKeySize }

        // Decapsulate → K_PQ.
        let kPQ = try self.mlkemPrivateKey!.decapsulate(ctBytes)
        // X25519 agreement.
        let serverX25519 = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: serverX25519Bytes)
        let kCL = try self.x25519SharedSecretBytes(with: serverX25519)

        // Reconstruct our own C_INIT (identical bytes to what we sent).
        let ourEk = Array(self.mlkemPrivateKey!.publicKey.rawRepresentation)
        let ourX25519 = Array(self.x25519PrivateKey.publicKey.rawRepresentation)

        let kString = Self.combinedSecretAsSSHString(kPQ: kPQ, kCL: kCL)
        let (exchangeHash, sessionID, keys) = self.finalize(
            cInit: ourEk + ourX25519,
            sReply: ctBytes + serverX25519Bytes,
            serverHostKey: message.hostKey,
            kString: kString,
            initialExchangeBytes: &initialExchangeBytes,
            allocator: allocator,
            expectedKeySizes: expectedKeySizes
        )

        guard message.hostKey.isValidSignature(message.signature, for: exchangeHash) else {
            throw NIOSSHError.invalidExchangeHashSignature
        }
        return KeyExchangeResult(sessionID: sessionID, keys: keys)
    }
}

@available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
extension MLKEM768X25519KeyExchange {
    /// X25519 agreement, returning the raw 32-byte secret (NOT mpint-trimmed). Rejects the
    /// all-zero (low-order point) secret in constant time, mirroring the classical curve guard.
    private func x25519SharedSecretBytes(
        with peer: Curve25519.KeyAgreement.PublicKey
    ) throws -> [UInt8] {
        let secret = try self.x25519PrivateKey.sharedSecretFromKeyAgreement(with: peer)
        let bytes = secret.withUnsafeBytes { Array($0) }
        let allORed = bytes.reduce(UInt8(0)) { $0 | $1 }
        guard allORed != 0 else {
            throw NIOSSHError.weakSharedSecret(exchangeAlgorithm: "mlkem768x25519-sha256")
        }
        return bytes
    }

    /// `K = SHA256(K_PQ ‖ K_CL)`, returned encoded as an SSH `string` (uint32 length ‖ bytes),
    /// per draft §2.5 — explicitly NOT an mpint. Both K_PQ and K_CL are fed as raw fixed-length
    /// 32-byte arrays (draft §2.4), so no mpint leading-zero/sign handling applies.
    private static func combinedSecretAsSSHString(kPQ: SymmetricKey, kCL: [UInt8]) -> [UInt8] {
        var hasher = SHA256()
        kPQ.withUnsafeBytes { hasher.update(bufferPointer: $0) }  // K_PQ (32 raw bytes)
        hasher.update(data: kCL)                                  // K_CL (32 raw bytes)
        let digest = hasher.finalize()                           // 32 bytes

        var out = [UInt8]()
        out.reserveCapacity(4 + SHA256.Digest.byteCount)
        let length = UInt32(SHA256.Digest.byteCount)             // 32
        out.append(UInt8(truncatingIfNeeded: length >> 24))
        out.append(UInt8(truncatingIfNeeded: length >> 16))
        out.append(UInt8(truncatingIfNeeded: length >> 8))
        out.append(UInt8(truncatingIfNeeded: length))
        out.append(contentsOf: digest)
        return out
    }

    /// Computes the exchange hash H and derives the session keys. `cInit`/`sReply` are the full
    /// concatenated blobs; `kString` is the SSH-string-encoded combined secret.
    private func finalize(
        cInit: [UInt8],
        sReply: [UInt8],
        serverHostKey: NIOSSHPublicKey,
        kString: [UInt8],
        initialExchangeBytes: inout ByteBuffer,
        allocator: ByteBufferAllocator,
        expectedKeySizes: ExpectedKeySizes
    ) -> (exchangeHash: SHA256.Digest, sessionID: ByteBuffer, keys: NIOSSHSessionKeys) {
        // initialExchangeBytes already holds V_C ‖ V_S ‖ I_C ‖ I_S (from the state machine).
        // H = SHA256( … ‖ string K_S ‖ string C_INIT ‖ string S_REPLY ‖ string K ).
        initialExchangeBytes.writeCompositeSSHString { $0.writeSSHHostKey(serverHostKey) }
        initialExchangeBytes.writeCompositeSSHString { $0.writeBytes(cInit) }
        initialExchangeBytes.writeCompositeSSHString { $0.writeBytes(sReply) }

        var hasher = SHA256()
        hasher.update(data: initialExchangeBytes.readableBytesView)
        hasher.update(data: kString)  // K as SSH string (NOT mpint)
        let exchangeHash = hasher.finalize()

        let sessionID: ByteBuffer
        if let previous = self.previousSessionIdentifier {
            sessionID = previous
        } else {
            var hashBytes = allocator.buffer(capacity: SHA256.Digest.byteCount)
            hashBytes.writeContiguousBytes(exchangeHash)
            sessionID = hashBytes
        }

        let keys = self.generateKeys(
            kString: kString,
            exchangeHash: exchangeHash,
            sessionID: sessionID,
            expectedKeySizes: expectedKeySizes
        )
        return (exchangeHash, sessionID, keys)
    }

    /// RFC 4253 §7.2 key derivation, SHA-256, with `K` seeded as an SSH string.
    private func generateKeys(
        kString: [UInt8],
        exchangeHash: SHA256.Digest,
        sessionID: ByteBuffer,
        expectedKeySizes: ExpectedKeySizes
    ) -> NIOSSHSessionKeys {
        var baseHasher = SHA256()
        baseHasher.update(data: kString)  // K (string) ‖ …
        exchangeHash.withUnsafeBytes { baseHasher.update(bufferPointer: $0) }  // … ‖ H

        let ivCS = Self.deriveKey(baseHasher, UInt8(ascii: "A"), sessionID, expectedKeySizes.ivSize)
        let ivSC = Self.deriveKey(baseHasher, UInt8(ascii: "B"), sessionID, expectedKeySizes.ivSize)
        let encCS = SymmetricKey(data: Self.deriveKey(baseHasher, UInt8(ascii: "C"), sessionID, expectedKeySizes.encryptionKeySize))
        let encSC = SymmetricKey(data: Self.deriveKey(baseHasher, UInt8(ascii: "D"), sessionID, expectedKeySizes.encryptionKeySize))
        let macCS = SymmetricKey(data: Self.deriveKey(baseHasher, UInt8(ascii: "E"), sessionID, expectedKeySizes.macKeySize))
        let macSC = SymmetricKey(data: Self.deriveKey(baseHasher, UInt8(ascii: "F"), sessionID, expectedKeySizes.macKeySize))

        switch self.ourRole {
        case .client:
            return NIOSSHSessionKeys(
                initialInboundIV: ivSC, initialOutboundIV: ivCS,
                inboundEncryptionKey: encSC, outboundEncryptionKey: encCS,
                inboundMACKey: macSC, outboundMACKey: macCS
            )
        case .server:
            return NIOSSHSessionKeys(
                initialInboundIV: ivCS, initialOutboundIV: ivSC,
                inboundEncryptionKey: encCS, outboundEncryptionKey: encSC,
                inboundMACKey: macCS, outboundMACKey: macSC
            )
        }
    }

    private static func deriveKey(
        _ baseHasher: SHA256,
        _ discriminator: UInt8,
        _ sessionID: ByteBuffer,
        _ length: Int
    ) -> [UInt8] {
        precondition(length <= 64, "sanity bound: no current SSH key scheme needs > 64 bytes")
        var h = baseHasher
        h.update(data: [discriminator])
        h.update(data: sessionID.readableBytesView)
        var out = Array(h.finalize())  // K1
        while out.count < length {
            var hn = baseHasher
            hn.update(data: out)
            out.append(contentsOf: hn.finalize())
        }
        return Array(out.prefix(length))
    }
}

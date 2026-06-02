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
import _CryptoExtras
import NIOCore
import NIOFoundationCompat
import XCTest

@testable import NIOSSH

final class HostKeyTests: XCTestCase {
    func testBasicEd25519SigningFlow() throws {
        let edKey = Curve25519.Signing.PrivateKey()
        let sshKey = NIOSSHPrivateKey(ed25519Key: edKey)

        let digest = SHA256.hash(data: Array("hello, world!".utf8))
        let signature = try assertNoThrowWithValue(sshKey.sign(digest: digest))

        // Naturally, this should verify.
        XCTAssertNoThrow(XCTAssertTrue(sshKey.publicKey.isValidSignature(signature, for: digest)))

        // Now let's try round-tripping through bytebuffer.
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHSignature(signature)

        let newSignature = try assertNoThrowWithValue(buffer.readSSHSignature()!)
        XCTAssertNoThrow(XCTAssertTrue(sshKey.publicKey.isValidSignature(newSignature, for: digest)))
    }

    func testBasicECDSAP256SigningFlow() throws {
        let ecdsaKey = P256.Signing.PrivateKey()
        let sshKey = NIOSSHPrivateKey(p256Key: ecdsaKey)

        let digest = SHA256.hash(data: Array("hello, world!".utf8))
        let signature = try assertNoThrowWithValue(sshKey.sign(digest: digest))

        // Naturally, this should verify.
        XCTAssertNoThrow(XCTAssertTrue(sshKey.publicKey.isValidSignature(signature, for: digest)))

        // Now let's try round-tripping through bytebuffer.
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHSignature(signature)

        let newSignature = try assertNoThrowWithValue(buffer.readSSHSignature()!)
        XCTAssertNoThrow(XCTAssertTrue(sshKey.publicKey.isValidSignature(newSignature, for: digest)))
    }

    func testBasicECDSAP384SigningFlow() throws {
        let ecdsaKey = P384.Signing.PrivateKey()
        let sshKey = NIOSSHPrivateKey(p384Key: ecdsaKey)

        let digest = SHA384.hash(data: Array("hello, world!".utf8))
        let signature = try assertNoThrowWithValue(sshKey.sign(digest: digest))

        // Naturally, this should verify.
        XCTAssertNoThrow(XCTAssertTrue(sshKey.publicKey.isValidSignature(signature, for: digest)))

        // Now let's try round-tripping through bytebuffer.
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHSignature(signature)

        let newSignature = try assertNoThrowWithValue(buffer.readSSHSignature()!)
        XCTAssertNoThrow(XCTAssertTrue(sshKey.publicKey.isValidSignature(newSignature, for: digest)))
    }

    func testBasicECDSAP521SigningFlow() throws {
        let ecdsaKey = P521.Signing.PrivateKey()
        let sshKey = NIOSSHPrivateKey(p521Key: ecdsaKey)

        let digest = SHA512.hash(data: Array("hello, world!".utf8))
        let signature = try assertNoThrowWithValue(sshKey.sign(digest: digest))

        // Naturally, this should verify.
        XCTAssertNoThrow(XCTAssertTrue(sshKey.publicKey.isValidSignature(signature, for: digest)))

        // Now let's try round-tripping through bytebuffer.
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHSignature(signature)

        let newSignature = try assertNoThrowWithValue(buffer.readSSHSignature()!)
        XCTAssertNoThrow(XCTAssertTrue(sshKey.publicKey.isValidSignature(newSignature, for: digest)))
    }

    // MARK: Public raw-bytes verify + public signature parse (hostkeys-prove primitives)

    /// Sign raw bytes with each key type, serialize the signature, parse it back via the public
    /// `NIOSSHSignature(buffer:)` init, and verify it via the public `isValidSignature(_:for: ByteBuffer)`
    /// overload. A flipped-byte buffer and a signature checked under a different key must both fail
    /// verification. This exercises the two fork primitives used to verify
    /// `hostkeys-prove-00@openssh.com` proofs. `label` tags each assertion message so a failure
    /// identifies the key type and which check tripped.
    private func assertRawBytesSignVerifyRoundTrips(
        _ sshKey: NIOSSHPrivateKey,
        wrongKey: NIOSSHPrivateKey,
        _ label: String,
        line: UInt = #line
    ) throws {
        // Use the SHA256 digest of a message as the signed bytes. The `sign(digest:)` API and the
        // `isValidSignature(_:for: ByteBuffer)` overload are symmetric on these bytes for all key
        // types (ed25519/ecdsa sign/verify them directly; RSA hashes them identically on both sides).
        let digest = SHA256.hash(data: Array("hostkeys-prove-00@openssh.com proof payload".utf8))
        let signedBytes = ByteBuffer(bytes: Array(digest))

        let signature = try assertNoThrowWithValue(sshKey.sign(digest: digest))

        // Serialize the signature the way the wire reply carries it, then parse it back via the
        // PUBLIC init that wraps `readSSHSignature()`.
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHSignature(signature)

        let parsed = try assertNoThrowWithValue(NIOSSHSignature(buffer: &buffer))
        XCTAssertNotNil(parsed, "\(label): expected a parsed signature", line: line)
        XCTAssertEqual(buffer.readableBytes, 0, "\(label): init(buffer:) must consume the whole signature", line: line)

        guard let parsed else { return }

        // The PUBLIC raw-bytes verify overload accepts the parsed signature over the original bytes.
        XCTAssertTrue(
            sshKey.publicKey.isValidSignature(parsed, for: signedBytes),
            "\(label): valid signature must verify over the original bytes",
            line: line
        )

        // Negative (tampered message): flipping a byte of the signed data must fail verification.
        var tampered = Array(digest)
        tampered[0] ^= 0xFF
        XCTAssertFalse(
            sshKey.publicKey.isValidSignature(parsed, for: ByteBuffer(bytes: tampered)),
            "\(label): signature must not verify over tampered bytes",
            line: line
        )

        // Negative (wrong key — the host-key-rotation threat model): a proof signed by one key must
        // NOT verify under a different host key's public key, even over the correct bytes. This is the
        // attack `HostKeyUpdater` defends against, and is independent of how the signed bytes are built.
        XCTAssertFalse(
            wrongKey.publicKey.isValidSignature(parsed, for: signedBytes),
            "\(label): signature must not verify under a different key",
            line: line
        )
    }

    func testPublicRawBytesVerifyRoundTripsEd25519() throws {
        try self.assertRawBytesSignVerifyRoundTrips(
            NIOSSHPrivateKey(ed25519Key: .init()),
            wrongKey: NIOSSHPrivateKey(ed25519Key: .init()),
            "ed25519"
        )
    }

    func testPublicRawBytesVerifyRoundTripsECDSAP256() throws {
        try self.assertRawBytesSignVerifyRoundTrips(
            NIOSSHPrivateKey(p256Key: .init()),
            wrongKey: NIOSSHPrivateKey(p256Key: .init()),
            "ecdsa-p256"
        )
    }

    func testPublicRawBytesVerifyRoundTripsRSA() throws {
        try self.assertRawBytesSignVerifyRoundTrips(
            NIOSSHPrivateKey(rsaSHA256Key: try _RSA.Signing.PrivateKey(keySize: .bits2048)),
            wrongKey: NIOSSHPrivateKey(rsaSHA256Key: try _RSA.Signing.PrivateKey(keySize: .bits2048)),
            "rsa"
        )
    }

    func testPublicSignatureParseReturnsNilOnTruncatedBuffer() throws {
        // A buffer that does not contain a complete signature yields nil (not a throw).
        let sshKey = NIOSSHPrivateKey(ed25519Key: .init())
        let signature = try assertNoThrowWithValue(sshKey.sign(digest: SHA256.hash(data: Array("x".utf8))))
        var full = ByteBufferAllocator().buffer(capacity: 1024)
        full.writeSSHSignature(signature)

        // Slice off the trailing bytes so the signature is incomplete.
        var truncated = full.getSlice(at: full.readerIndex, length: full.readableBytes - 4)!
        let parsed = try NIOSSHSignature(buffer: &truncated)
        XCTAssertNil(parsed)
    }

    func testEd25519FailsVerificationWithDifferentKeys() throws {
        let edKey = Curve25519.Signing.PrivateKey()
        let sshKey = NIOSSHPrivateKey(ed25519Key: edKey)

        let digest = SHA256.hash(data: Array("hello, world!".utf8))
        let signature = try assertNoThrowWithValue(sshKey.sign(digest: digest))

        let otherSSHKey = NIOSSHPrivateKey(ed25519Key: .init())

        // Naturally, this should not verify.
        XCTAssertNoThrow(XCTAssertFalse(otherSSHKey.publicKey.isValidSignature(signature, for: digest)))

        // Now let's try round-tripping through bytebuffer.
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHSignature(signature)

        let newSignature = try assertNoThrowWithValue(buffer.readSSHSignature()!)
        XCTAssertNoThrow(XCTAssertFalse(otherSSHKey.publicKey.isValidSignature(newSignature, for: digest)))
    }

    func testECDASP256FailsVerificationWithDifferentKeys() throws {
        let ecdsaKey = P256.Signing.PrivateKey()
        let sshKey = NIOSSHPrivateKey(p256Key: ecdsaKey)

        let digest = SHA256.hash(data: Array("hello, world!".utf8))
        let signature = try assertNoThrowWithValue(sshKey.sign(digest: digest))

        let otherSSHKey = NIOSSHPrivateKey(p256Key: .init())

        // Naturally, this should not verify.
        XCTAssertNoThrow(XCTAssertFalse(otherSSHKey.publicKey.isValidSignature(signature, for: digest)))

        // Now let's try round-tripping through bytebuffer.
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHSignature(signature)

        let newSignature = try assertNoThrowWithValue(buffer.readSSHSignature()!)
        XCTAssertNoThrow(XCTAssertFalse(otherSSHKey.publicKey.isValidSignature(newSignature, for: digest)))
    }

    func testECDASP384FailsVerificationWithDifferentKeys() throws {
        let ecdsaKey = P384.Signing.PrivateKey()
        let sshKey = NIOSSHPrivateKey(p384Key: ecdsaKey)

        let digest = SHA384.hash(data: Array("hello, world!".utf8))
        let signature = try assertNoThrowWithValue(sshKey.sign(digest: digest))

        let otherSSHKey = NIOSSHPrivateKey(p384Key: .init())

        // Naturally, this should not verify.
        XCTAssertNoThrow(XCTAssertFalse(otherSSHKey.publicKey.isValidSignature(signature, for: digest)))

        // Now let's try round-tripping through bytebuffer.
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHSignature(signature)

        let newSignature = try assertNoThrowWithValue(buffer.readSSHSignature()!)
        XCTAssertNoThrow(XCTAssertFalse(otherSSHKey.publicKey.isValidSignature(newSignature, for: digest)))
    }

    func testECDASP521FailsVerificationWithDifferentKeys() throws {
        let ecdsaKey = P521.Signing.PrivateKey()
        let sshKey = NIOSSHPrivateKey(p521Key: ecdsaKey)

        let digest = SHA512.hash(data: Array("hello, world!".utf8))
        let signature = try assertNoThrowWithValue(sshKey.sign(digest: digest))

        let otherSSHKey = NIOSSHPrivateKey(p521Key: .init())

        // Naturally, this should not verify.
        XCTAssertNoThrow(XCTAssertFalse(otherSSHKey.publicKey.isValidSignature(signature, for: digest)))

        // Now let's try round-tripping through bytebuffer.
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHSignature(signature)

        let newSignature = try assertNoThrowWithValue(buffer.readSSHSignature()!)
        XCTAssertNoThrow(XCTAssertFalse(otherSSHKey.publicKey.isValidSignature(newSignature, for: digest)))
    }

    func testEd25519FailsVerificationWithWrongAlgorithms() throws {
        let edKey = Curve25519.Signing.PrivateKey()
        let sshKey = NIOSSHPrivateKey(ed25519Key: edKey)

        let digest = SHA256.hash(data: Array("hello, world!".utf8))
        let signature = try assertNoThrowWithValue(sshKey.sign(digest: digest))

        let otherSSHKey = NIOSSHPrivateKey(p256Key: .init())

        // Naturally, this should not verify.
        XCTAssertNoThrow(XCTAssertFalse(otherSSHKey.publicKey.isValidSignature(signature, for: digest)))

        // Now let's try round-tripping through bytebuffer.
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHSignature(signature)

        let newSignature = try assertNoThrowWithValue(buffer.readSSHSignature()!)
        XCTAssertNoThrow(XCTAssertFalse(otherSSHKey.publicKey.isValidSignature(newSignature, for: digest)))
    }

    func testECDASP256FailsVerificationWithWrongAlgorithms() throws {
        let ecdsaKey = P256.Signing.PrivateKey()
        let sshKey = NIOSSHPrivateKey(p256Key: ecdsaKey)

        let digest = SHA256.hash(data: Array("hello, world!".utf8))
        let signature = try assertNoThrowWithValue(sshKey.sign(digest: digest))

        let otherSSHKey = NIOSSHPrivateKey(ed25519Key: .init())

        // Naturally, this should not verify.
        XCTAssertNoThrow(XCTAssertFalse(otherSSHKey.publicKey.isValidSignature(signature, for: digest)))

        // Now let's try round-tripping through bytebuffer.
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHSignature(signature)

        let newSignature = try assertNoThrowWithValue(buffer.readSSHSignature()!)
        XCTAssertNoThrow(XCTAssertFalse(otherSSHKey.publicKey.isValidSignature(newSignature, for: digest)))
    }

    func testECDASP384FailsVerificationWithWrongAlgorithms() throws {
        let ecdsaKey = P384.Signing.PrivateKey()
        let sshKey = NIOSSHPrivateKey(p384Key: ecdsaKey)

        let digest = SHA384.hash(data: Array("hello, world!".utf8))
        let signature = try assertNoThrowWithValue(sshKey.sign(digest: digest))

        let otherSSHKey = NIOSSHPrivateKey(ed25519Key: .init())

        // Naturally, this should not verify.
        XCTAssertNoThrow(XCTAssertFalse(otherSSHKey.publicKey.isValidSignature(signature, for: digest)))

        // Now let's try round-tripping through bytebuffer.
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHSignature(signature)

        let newSignature = try assertNoThrowWithValue(buffer.readSSHSignature()!)
        XCTAssertNoThrow(XCTAssertFalse(otherSSHKey.publicKey.isValidSignature(newSignature, for: digest)))
    }

    func testECDASP521FailsVerificationWithWrongAlgorithms() throws {
        let ecdsaKey = P521.Signing.PrivateKey()
        let sshKey = NIOSSHPrivateKey(p521Key: ecdsaKey)

        let digest = SHA512.hash(data: Array("hello, world!".utf8))
        let signature = try assertNoThrowWithValue(sshKey.sign(digest: digest))

        let otherSSHKey = NIOSSHPrivateKey(ed25519Key: .init())

        // Naturally, this should not verify.
        XCTAssertNoThrow(XCTAssertFalse(otherSSHKey.publicKey.isValidSignature(signature, for: digest)))

        // Now let's try round-tripping through bytebuffer.
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHSignature(signature)

        let newSignature = try assertNoThrowWithValue(buffer.readSSHSignature()!)
        XCTAssertNoThrow(XCTAssertFalse(otherSSHKey.publicKey.isValidSignature(newSignature, for: digest)))
    }

    func testUnrecognisedKey() throws {
        // A genuinely unknown algorithm id must still be rejected. `ssh-rsa` is now a
        // RECOGNISED host-key type (C3), so use `ssh-dss` (DSA, unsupported) which routes
        // through readCertifiedKeyWithoutKeyPrefix → baseKeyPrefixForKeyPrefix → throws.
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHString("ssh-dss".utf8)

        XCTAssertThrowsError(try buffer.readSSHHostKey()) { error in
            XCTAssertEqual((error as? NIOSSHError).map { $0.type }, .unknownPublicKey)
        }
    }

    func testRSAHostKeyIsRecognised() throws {
        // ssh-rsa is now a RECOGNISED host-key type (C3). A full ssh-rsa blob round-trips
        // through write/read and reads back as the same recognised RSA public key.
        let rsa = NIOSSHPrivateKey(rsaSHA256Key: try _RSA.Signing.PrivateKey(keySize: .bits2048))
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHHostKey(rsa.publicKey)
        let parsed = try XCTUnwrap(try buffer.readSSHHostKey())
        XCTAssertEqual(parsed, rsa.publicKey)
    }

    func testInvalidDomainParametersForECDSAP256() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHString("ecdsa-sha2-nistp256".utf8)
        buffer.writeSSHString("nistp384".utf8)  // Surprise!

        XCTAssertThrowsError(try buffer.readSSHHostKey()) { error in
            XCTAssertEqual((error as? NIOSSHError).map { $0.type }, .invalidDomainParametersForKey)
        }
    }

    func testInvalidDomainParametersForECDSAP384() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHString("ecdsa-sha2-nistp384".utf8)
        buffer.writeSSHString("nistp256".utf8)  // Surprise!

        XCTAssertThrowsError(try buffer.readSSHHostKey()) { error in
            XCTAssertEqual((error as? NIOSSHError).map { $0.type }, .invalidDomainParametersForKey)
        }
    }

    func testInvalidDomainParametersForECDSAP521() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHString("ecdsa-sha2-nistp521".utf8)
        buffer.writeSSHString("nistp384".utf8)  // Surprise!

        XCTAssertThrowsError(try buffer.readSSHHostKey()) { error in
            XCTAssertEqual((error as? NIOSSHError).map { $0.type }, .invalidDomainParametersForKey)
        }
    }

    func testUnrecognisedSignature() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHString("ssh-rsa".utf8)

        XCTAssertThrowsError(try buffer.readSSHSignature()) { error in
            XCTAssertEqual((error as? NIOSSHError).map { $0.type }, .unknownSignature)
        }
    }

    func testLoadingEd25519KeyFromFileRoundTrips() throws {
        let keyData =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJfkNV4OS33ImTXvorZr72q4v5XhVEQKfvqsxOEJ/XaR lukasa@MacBook-Pro.local"
        XCTAssertNoThrow(
            try self.roundTripKey(keyData: keyData, label: "ssh-ed25519", comment: " lukasa@MacBook-Pro.local")
        )
    }

    func testLoadingP256KeyFromFileRoundTrips() throws {
        let keyData =
            "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIZS1APJofiPeoATC/VC4kKi7xRPdz934nSkFLTc0whYi3A8hEKHAOX9edgL1UWxRqRGQZq2wvvAIjAO9kCeiQA= lukasa@MacBook-Pro.local"
        XCTAssertNoThrow(
            try self.roundTripKey(keyData: keyData, label: "ecdsa-sha2-nistp256", comment: " lukasa@MacBook-Pro.local")
        )
    }

    func testLoadingP384KeyFromFileRoundTrips() throws {
        let keyData =
            "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBJPOgAXHijSxoZBiyhSDOR3eUELUoc+hqh/SY1Wq4/562jThf6Q+tjVzZTMWZMAP4S6DD2qZswsRvisxXkcZDOw5bvyk0WmezYvjUP6TZII/0BDVTotCf4SxukEtcqBZqg== lukasa@MacBook-Pro.local"
        XCTAssertNoThrow(
            try self.roundTripKey(keyData: keyData, label: "ecdsa-sha2-nistp384", comment: " lukasa@MacBook-Pro.local")
        )
    }

    func testLoadingP521KeyFromFileRoundTrips() throws {
        let keyData =
            "ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBACkfM3aZf9sgjAkncWtK6A295sdghn1GG1BKJ+hQfD2VBIJxSQDnPOocNIQQZEo3zs1kvwUXOIgWANJqbOiv77tCACxWRRYmAvM3hzgcEOhPROROG+KGvuDAWW6ZuCkaW0QnseR7Yn0+q/+/jai3tNNDWrbVLDesDj5Aq5xq1yrKDHGEA== lukasa@MacBook-Pro.local"
        XCTAssertNoThrow(
            try self.roundTripKey(keyData: keyData, label: "ecdsa-sha2-nistp521", comment: " lukasa@MacBook-Pro.local")
        )
    }

    func testMissingCommentIsTolerated() throws {
        let keyData = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJfkNV4OS33ImTXvorZr72q4v5XhVEQKfvqsxOEJ/XaR"
        XCTAssertNoThrow(try self.roundTripKey(keyData: keyData, label: "ssh-ed25519", comment: ""))
    }

    func testDripFeedingKey() throws {
        let keyData = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJfkNV4OS33ImTXvorZr72q4v5XhVEQKfvqsxOEJ/XaR"
        for index in keyData.indices.dropLast() {
            XCTAssertThrowsError(try NIOSSHPublicKey(openSSHPublicKey: String(keyData[..<index]))) { error in
                XCTAssertEqual((error as? NIOSSHError)?.type, .invalidOpenSSHPublicKey)
            }
        }
    }

    func testKeyLiesAboutItsType() throws {
        // Secretly P384
        let keyData =
            "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBJPOgAXHijSxoZBiyhSDOR3eUELUoc+hqh/SY1Wq4/562jThf6Q+tjVzZTMWZMAP4S6DD2qZswsRvisxXkcZDOw5bvyk0WmezYvjUP6TZII/0BDVTotCf4SxukEtcqBZqg== lukasa@MacBook-Pro.local"
        XCTAssertThrowsError(try NIOSSHPublicKey(openSSHPublicKey: keyData)) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .invalidOpenSSHPublicKey)
        }
    }

    private func roundTripKey(keyData: String, label: String, comment: String) throws {
        let key = try assertNoThrowWithValue(NIOSSHPublicKey(openSSHPublicKey: keyData))
        var keyBuffer = ByteBufferAllocator().buffer(capacity: 1024)
        keyBuffer.writeSSHHostKey(key)
        let expectedKeyData =
            "\(label) \(keyBuffer.readData(length: keyBuffer.readableBytes)!.base64EncodedString())\(comment)"
        XCTAssertEqual(keyData, expectedKeyData)
    }
}

//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2026 the SwiftNIO project authors
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
import XCTest

@testable import NIOSSH

/// A minimal `Digest`-conforming wrapper over arbitrary bytes, used to exercise the EXACT
/// production KEX verify path (`isValidSignature(_:for: DigestBytes)` Digest overload at
/// `EllipticCurveKeyExchange.swift:161`) with a captured exchange hash. The verify path only
/// touches `withUnsafeBytes` (ContiguousBytes); the other conformances are trivial.
struct RawExchangeHashDigest: Digest {
    static var byteCount: Int { 0 }  // unused by the verify path
    let bytes: [UInt8]

    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try self.bytes.withUnsafeBytes(body)
    }

    func makeIterator() -> Array<UInt8>.Iterator { self.bytes.makeIterator() }
    var description: String { "RawExchangeHashDigest(\(self.bytes.count) bytes)" }
    static func == (lhs: RawExchangeHashDigest, rhs: RawExchangeHashDigest) -> Bool { lhs.bytes == rhs.bytes }
    func hash(into hasher: inout Hasher) { hasher.combine(self.bytes) }
}

/// Golden-vector verification for RSA SHA-2 host-key signatures (C3).
///
/// CRITICAL (C1 lesson): hermetic NIO-to-NIO round-trip tests prove only self-consistency —
/// both ends run the same (possibly wrong) code and agree with each other. These vectors are
/// the NON-CIRCULAR gate: the `(public key, message H, signature)` triple was produced by an
/// independent implementation (OpenSSL `dgst -sha512/-sha256 -sign`) using a fixed RSA host
/// key, and the signature was independently re-verified with `openssl dgst -verify`
/// ("Verified OK") BEFORE being committed here. The public key string is the OpenSSH wire
/// encoding of the SAME fixed key exported by real `ssh-keygen -e -m PKCS8`.
///
/// OpenSSL and OpenSSH produce byte-identical `RSASSA-PKCS1-v1_5(SHA-x, message)` encodings
/// (same DigestInfo OID + PKCS#1 v1.5 padding), so a vector that OpenSSL signs and re-verifies
/// is exactly what a real OpenSSH server emits for an `rsa-sha2-512` / `rsa-sha2-256` host-key
/// signature over the exchange hash.
///
/// Provenance (see docs/superpowers/plans/2026-05-29-c3-rsa-host-key-verification.md Task 6):
///   - Fixed host key: SSHClientKit `test-fixtures/rsa-host/ssh_host_rsa_key` (3072-bit RSA,
///     fingerprint SHA256:FZxPeTbDW84i1FGGBijTaGZqTE1YdVQIusgepKbclQo, comment c3-golden-host).
///   - H: a fixed 64-byte message standing in for the KEX exchange hash (the RSA layer signs
///     SHA-x(H), so H's size is irrelevant to the test's fidelity).
///   - Signatures: `openssl dgst -sha512/-sha256 -sign <key> H` ; re-verified with
///     `openssl dgst -sha512/-sha256 -verify <pub.pem> -signature sig H` → "Verified OK".
final class RSAHostKeyVerificationVectorTests: XCTestCase {
    /// OpenSSH wire encoding of the fixed 3072-bit RSA host key (ssh-keygen output).
    static let hostKeyOpenSSHString =
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDpuuMCAyAKv5nsb0e3tnHe7CGdPhjBEV+BTAdhSC9Vosy0i"
        + "us0SimgqSM+q72puS/jEnH/3uSLArjXyhY4WPvwYWaiDq4MaPfo0fELTlxx9xoNJNm/tnJifg8ZiErvz5AS"
        + "eWG+twtIPpt5gEcyNeMdkPxkH4CI/XqzuKy7jMv1gWk8emJsWOQyk5ApRBP/ETZfcjnzUdx+wIUNZXA7LGC"
        + "qpJUaR+skbf3Tkk/hdYOT9TH+DJAG8Z9ClPxE0ToUEQ885CcIZLVU+/LIQUPkPImIaqoBjQgRJaM3IXdPIX"
        + "Yk+EYi9Q+xZs6lO6MyQ0wrhx6HWGmki2Qk+Fg4sTcnPyNuJqN38zyTnl8hZoWZDrIhZrnlSIb/5j0AgbnHO"
        + "dsS9HQW0yl7KTVp355R5ujCUHP/jjgL7OKmAP1ZH1VrefPh3qZ034uuS5LWo3+Ld7xb2ajxbSj7L2KfmjFX"
        + "u5MXLW3flLPyboap2kvQUUXmyuluUgtuvyNcdDUYTov10wY2HCU= c3-golden-host"

    /// The fixed 64-byte "exchange hash" message that was signed.
    static let exchangeHashB64 =
        "DRQbIikwNz5FTFNaYWhvdn2Ei5KZoKeutbzDytHY3+bt9PsCCRAXHiUsMzpBSE9WXWRrcnmAh46VnKOqsbi/xg=="

    /// Full SSH-wire signature blob `string("rsa-sha2-512") || string(rawSig)` for H.
    static let signatureBlob512B64 =
        "AAAADHJzYS1zaGEyLTUxMgAAAYBte9BJqBkbIG4e95xz+cC89Az/CsAAaHatIpkm1mDuZfpmhAu2tZrz2khF/Ncm"
        + "PuZrkb4UWAr/f9aj3zD9pwcCdabyFxK35IYzmOSNt4cefycODnBRdNwqI+/gfOKp5iCpN3IWS/ePaYsnGwJZzt1"
        + "Uc53i2FpUKAtucFlrd8F5wzg8+c6LyqSyjUec+6xYKRCvNIkwXqES75lrRIJhEFNxjuKLx6qLG2cWvHCsPfNUsv"
        + "RNBa2+tUMIFW+6LTc9L37OFA4YN0vjZrbtV0RzycNgRhRo+j9ujv3hVQnkcN/E98Jbv5PKzM6yFw1tSfI5oYisW"
        + "vX0oKPKjBVW5mg7cG4rWNwVv0iOlSzouZ4nQ4Q4zJtttTN3ti1Z8qEaCwGTVvc7Fn1oINvvH+WX/wDaBwYzpXo3"
        + "lQqvMNz3iLhINp+Z0VSG0kD3ZEHqVxzPkKf5FPMZLhRgtHbA9rU4eDB8S7uPyA/Lqd1Gbh0q2wgSzf6gCoM22e+"
        + "dnwSeyWKah0h2VGM="

    /// Full SSH-wire signature blob `string("rsa-sha2-256") || string(rawSig)` for H.
    static let signatureBlob256B64 =
        "AAAADHJzYS1zaGEyLTI1NgAAAYCfaNfWSkbuE7lBS7MadLoJSVL0SxsA0plX0d57sFcJ5xm7XByRQ+GnNmyMj5DB5"
        + "ZjYgLrSlCSuEMRxRN0sAJ2kVy4i1k+7ZHvXXujSEA+ydm+IpPUJbQElUeeHDGIH2iFWM+NzX/5kVEWnu/ova+Js"
        + "wjVPw5PmlZxdKWM+E8Chd1fgdE5om0WPHlD8pP7ceNF8dBmJYxisIaIfozjwGb+deW3N+O7LyK++5GMjbSnAT2yn"
        + "Jk2PYs5AviBqdAg2OChvh1VuqQ0f9+QfEXQuy/VBAJxr46EClPEg4gmbapJ6L4yHSL+nur6FTJOhNGMmACpH1RgQ"
        + "cjj9DfXIji3Bxxil00k0KvlaYYbWjincQv1zHVA0oQS2X6OvOaQiQaWfiddvcGB33+9Oi7Oesq7Q96cs2CI35uHr"
        + "DdC4KmFmxbOj9eQr0Tdyq/PNaTMTM50+eC9EH6x/OdFdKAeG2HQj+yne9bwTENqfotRKuFIgj7V51U7B4646d3+7"
        + "XhuFikRdQTU="

    private func decodeBuffer(_ b64: String) throws -> ByteBuffer {
        let data = try XCTUnwrap(Data(base64Encoded: b64))
        var buffer = ByteBufferAllocator().buffer(capacity: data.count)
        buffer.writeContiguousBytes(data)
        return buffer
    }

    func testRealRSASHA512SignatureVerifies() throws {
        let hostKey = try NIOSSHPublicKey(openSSHPublicKey: Self.hostKeyOpenSSHString)
        var sigBuf = try self.decodeBuffer(Self.signatureBlob512B64)
        let sig = try XCTUnwrap(try sigBuf.readSSHSignature())
        let h = try self.decodeBuffer(Self.exchangeHashB64)

        // The host key parses as .rsaSHA256 (ssh-rsa blob); the rsa-sha2-512 signature drives
        // SHA-512 via the verify-side cross-tag fix. The ByteBuffer overload hashes the same
        // H bytes as the KEX-path Digest overload, so it is wire-equivalent for this vector.
        XCTAssertTrue(hostKey.isValidSignature(sig, for: h))
    }

    func testRealRSASHA256SignatureVerifies() throws {
        let hostKey = try NIOSSHPublicKey(openSSHPublicKey: Self.hostKeyOpenSSHString)
        var sigBuf = try self.decodeBuffer(Self.signatureBlob256B64)
        let sig = try XCTUnwrap(try sigBuf.readSSHSignature())
        let h = try self.decodeBuffer(Self.exchangeHashB64)

        XCTAssertTrue(hostKey.isValidSignature(sig, for: h))
    }

    /// Exercise the EXACT production KEX Digest overload with the real vector (the live host-key
    /// verify path at EllipticCurveKeyExchange.swift:161).
    func testRealRSASHA512SignatureVerifiesViaDigestOverload() throws {
        let hostKey = try NIOSSHPublicKey(openSSHPublicKey: Self.hostKeyOpenSSHString)
        var sigBuf = try self.decodeBuffer(Self.signatureBlob512B64)
        let sig = try XCTUnwrap(try sigBuf.readSSHSignature())
        let hBytes = Array(try XCTUnwrap(Data(base64Encoded: Self.exchangeHashB64)))
        let digest = RawExchangeHashDigest(bytes: hBytes)

        XCTAssertTrue(hostKey.isValidSignature(sig, for: digest))
    }

    func testRealRSASHA256SignatureVerifiesViaDigestOverload() throws {
        let hostKey = try NIOSSHPublicKey(openSSHPublicKey: Self.hostKeyOpenSSHString)
        var sigBuf = try self.decodeBuffer(Self.signatureBlob256B64)
        let sig = try XCTUnwrap(try sigBuf.readSSHSignature())
        let hBytes = Array(try XCTUnwrap(Data(base64Encoded: Self.exchangeHashB64)))
        let digest = RawExchangeHashDigest(bytes: hBytes)

        XCTAssertTrue(hostKey.isValidSignature(sig, for: digest))
    }

    func testRSASHA512SignatureRejectsTamperedExchangeHash() throws {
        let hostKey = try NIOSSHPublicKey(openSSHPublicKey: Self.hostKeyOpenSSHString)
        var sigBuf = try self.decodeBuffer(Self.signatureBlob512B64)
        let sig = try XCTUnwrap(try sigBuf.readSSHSignature())

        // Flip a single byte of H → must fail verification.
        var data = try XCTUnwrap(Data(base64Encoded: Self.exchangeHashB64))
        data[0] ^= 0x01
        var tampered = ByteBufferAllocator().buffer(capacity: data.count)
        tampered.writeContiguousBytes(data)

        XCTAssertFalse(hostKey.isValidSignature(sig, for: tampered))
    }

    func testRSASHA256SignatureRejectsTamperedExchangeHash() throws {
        let hostKey = try NIOSSHPublicKey(openSSHPublicKey: Self.hostKeyOpenSSHString)
        var sigBuf = try self.decodeBuffer(Self.signatureBlob256B64)
        let sig = try XCTUnwrap(try sigBuf.readSSHSignature())

        var data = try XCTUnwrap(Data(base64Encoded: Self.exchangeHashB64))
        data[10] ^= 0x80
        var tampered = ByteBufferAllocator().buffer(capacity: data.count)
        tampered.writeContiguousBytes(data)

        XCTAssertFalse(hostKey.isValidSignature(sig, for: tampered))
    }

    /// Negative: the rsa-sha2-512 signature must NOT verify if interpreted as rsa-sha2-256
    /// (wrong inner hash). Re-frames the committed 512 raw bytes under the 256 algorithm name
    /// and asserts rejection — pins that the signature *variant* tag selects the hash.
    func testRSASignatureVariantTagSelectsHash() throws {
        let hostKey = try NIOSSHPublicKey(openSSHPublicKey: Self.hostKeyOpenSSHString)

        // Re-read the 512 blob to extract its raw signature bytes, then re-frame under 256.
        var orig = try self.decodeBuffer(Self.signatureBlob512B64)
        _ = orig.readSSHString()  // skip "rsa-sha2-512"
        let rawSig = try XCTUnwrap(orig.readSSHString())

        var reframed = ByteBufferAllocator().buffer(capacity: rawSig.readableBytes + 32)
        reframed.writeSSHString("rsa-sha2-256".utf8)
        var rawSigCopy = rawSig
        reframed.writeSSHString(&rawSigCopy)
        let mislabeled = try XCTUnwrap(try reframed.readSSHSignature())

        let h = try self.decodeBuffer(Self.exchangeHashB64)
        // The 512 signature evaluated with SHA-256 inner hash must fail.
        XCTAssertFalse(hostKey.isValidSignature(mislabeled, for: h))
    }
}

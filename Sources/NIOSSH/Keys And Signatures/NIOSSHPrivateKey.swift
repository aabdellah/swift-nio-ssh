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

@preconcurrency import Crypto
import _CryptoExtras
import NIOCore

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// An SSH private key.
///
/// This object identifies a single SSH entity, usually a server. It is used as part of the SSH handshake and key exchange process,
/// and is also presented to clients that want to validate that they are communicating with the appropriate server. Clients use
/// this key to sign data in order to validate their identity as part of user auth.
///
/// Users cannot do much with this key other than construct it, but NIO uses it internally.
public struct NIOSSHPrivateKey: Sendable {
    /// The actual key structure used to perform the key operations.
    internal var backingKey: BackingKey

    private init(backingKey: BackingKey) {
        self.backingKey = backingKey
    }

    public init(ed25519Key key: Curve25519.Signing.PrivateKey) {
        self.backingKey = .ed25519(key)
    }

    public init(p256Key key: P256.Signing.PrivateKey) {
        self.backingKey = .ecdsaP256(key)
    }

    public init(p384Key key: P384.Signing.PrivateKey) {
        self.backingKey = .ecdsaP384(key)
    }

    public init(p521Key key: P521.Signing.PrivateKey) {
        self.backingKey = .ecdsaP521(key)
    }

    public init(rsaSHA256Key key: _RSA.Signing.PrivateKey) {
        self.backingKey = .rsaSHA256(key)
    }

    public init(rsaSHA512Key key: _RSA.Signing.PrivateKey) {
        self.backingKey = .rsaSHA512(key)
    }

    #if canImport(Darwin)
    public init(secureEnclaveP256Key key: SecureEnclave.P256.Signing.PrivateKey) {
        self.backingKey = .secureEnclaveP256(key)
    }
    #endif

    // The algorithms that apply to this host key.
    internal var hostKeyAlgorithms: [Substring] {
        switch self.backingKey {
        case .ed25519:
            return ["ssh-ed25519"]
        case .ecdsaP256:
            return ["ecdsa-sha2-nistp256"]
        case .ecdsaP384:
            return ["ecdsa-sha2-nistp384"]
        case .ecdsaP521:
            return ["ecdsa-sha2-nistp521"]
        case .rsaSHA256:
            return ["rsa-sha2-256"]
        case .rsaSHA512:
            return ["rsa-sha2-512"]
        #if canImport(Darwin)
        case .secureEnclaveP256:
            return ["ecdsa-sha2-nistp256"]
        #endif
        }
    }

    /// The underlying RSA key + whether it is currently tagged SHA-512, or nil for
    /// non-RSA keys. Used to re-wrap with a different RFC 8332 signature variant.
    internal var rsaKeyAndIsSHA512: (key: _RSA.Signing.PrivateKey, isSHA512: Bool)? {
        switch self.backingKey {
        case .rsaSHA256(let key): return (key, false)
        case .rsaSHA512(let key): return (key, true)
        default: return nil
        }
    }
}

extension NIOSSHPrivateKey {
    /// The various key types that can be used with NIOSSH.
    internal enum BackingKey {
        case ed25519(Curve25519.Signing.PrivateKey)
        case ecdsaP256(P256.Signing.PrivateKey)
        case ecdsaP384(P384.Signing.PrivateKey)
        case ecdsaP521(P521.Signing.PrivateKey)
        case rsaSHA256(_RSA.Signing.PrivateKey)
        case rsaSHA512(_RSA.Signing.PrivateKey)

        #if canImport(Darwin)
        case secureEnclaveP256(SecureEnclave.P256.Signing.PrivateKey)
        #endif
    }
}

extension NIOSSHPrivateKey {
    func sign<DigestBytes: Digest>(digest: DigestBytes) throws -> NIOSSHSignature {
        switch self.backingKey {
        case .ed25519(let key):
            let signature = try digest.withUnsafeBytes { ptr in
                try key.signature(for: ptr)
            }
            return NIOSSHSignature(backingSignature: .ed25519(.data(signature)))
        case .ecdsaP256(let key):
            let signature = try digest.withUnsafeBytes { ptr in
                try key.signature(for: ptr)
            }
            return NIOSSHSignature(backingSignature: .ecdsaP256(signature))
        case .ecdsaP384(let key):
            let signature = try digest.withUnsafeBytes { ptr in
                try key.signature(for: ptr)
            }
            return NIOSSHSignature(backingSignature: .ecdsaP384(signature))
        case .ecdsaP521(let key):
            let signature = try digest.withUnsafeBytes { ptr in
                try key.signature(for: ptr)
            }
            return NIOSSHSignature(backingSignature: .ecdsaP521(signature))
        case .rsaSHA256(let key):
            // RFC 8332 §3: rsa-sha2-256 signs SHA-256 OF the message bytes (here the exchange
            // hash). The Digest overload of `_RSA.Signing.PrivateKey.signature(for:padding:)`
            // does NOT rehash — it treats the supplied bytes as the FINAL hash and PKCS#1-pads
            // with the SHA-256 DigestInfo OID. So we must hand it SHA-256(H), not H, to stay
            // symmetric with isValidSignature(_:for: digest) and OpenSSH (mirrors `sign(_ payload:)`).
            let signedDigest = digest.withUnsafeBytes { SHA256.hash(data: $0) }
            let signature = try key.signature(for: signedDigest, padding: .insecurePKCS1v1_5)
            return NIOSSHSignature(backingSignature: .rsaSHA256(.data(signature.rawRepresentation)))
        case .rsaSHA512(let key):
            let signedDigest = digest.withUnsafeBytes { SHA512.hash(data: $0) }
            let signature = try key.signature(for: signedDigest, padding: .insecurePKCS1v1_5)
            return NIOSSHSignature(backingSignature: .rsaSHA512(.data(signature.rawRepresentation)))

        #if canImport(Darwin)
        case .secureEnclaveP256(let key):
            let signature = try digest.withUnsafeBytes { ptr in
                try key.signature(for: ptr)
            }
            return NIOSSHSignature(backingSignature: .ecdsaP256(signature))
        #endif
        }
    }

    func sign(_ payload: UserAuthSignablePayload) throws -> NIOSSHSignature {
        switch self.backingKey {
        case .ed25519(let key):
            let signature = try key.signature(for: payload.bytes.readableBytesView)
            return NIOSSHSignature(backingSignature: .ed25519(.data(signature)))
        case .ecdsaP256(let key):
            let signature = try key.signature(for: payload.bytes.readableBytesView)
            return NIOSSHSignature(backingSignature: .ecdsaP256(signature))
        case .ecdsaP384(let key):
            let signature = try key.signature(for: payload.bytes.readableBytesView)
            return NIOSSHSignature(backingSignature: .ecdsaP384(signature))
        case .ecdsaP521(let key):
            let signature = try key.signature(for: payload.bytes.readableBytesView)
            return NIOSSHSignature(backingSignature: .ecdsaP521(signature))
        case .rsaSHA256(let key):
            let digest = SHA256.hash(data: payload.bytes.readableBytesView)
            let signature = try key.signature(for: digest, padding: .insecurePKCS1v1_5)
            return NIOSSHSignature(backingSignature: .rsaSHA256(.data(signature.rawRepresentation)))
        case .rsaSHA512(let key):
            let digest = SHA512.hash(data: payload.bytes.readableBytesView)
            let signature = try key.signature(for: digest, padding: .insecurePKCS1v1_5)
            return NIOSSHSignature(backingSignature: .rsaSHA512(.data(signature.rawRepresentation)))
        #if canImport(Darwin)
        case .secureEnclaveP256(let key):
            let signature = try key.signature(for: payload.bytes.readableBytesView)
            return NIOSSHSignature(backingSignature: .ecdsaP256(signature))
        #endif
        }
    }
}

extension NIOSSHPrivateKey {
    /// Obtains the public key for a corresponding private key.
    public var publicKey: NIOSSHPublicKey {
        switch self.backingKey {
        case .ed25519(let privateKey):
            return NIOSSHPublicKey(backingKey: .ed25519(privateKey.publicKey))
        case .ecdsaP256(let privateKey):
            return NIOSSHPublicKey(backingKey: .ecdsaP256(privateKey.publicKey))
        case .ecdsaP384(let privateKey):
            return NIOSSHPublicKey(backingKey: .ecdsaP384(privateKey.publicKey))
        case .ecdsaP521(let privateKey):
            return NIOSSHPublicKey(backingKey: .ecdsaP521(privateKey.publicKey))
        case .rsaSHA256(let privateKey):
            return NIOSSHPublicKey(backingKey: .rsaSHA256(privateKey.publicKey))
        case .rsaSHA512(let privateKey):
            return NIOSSHPublicKey(backingKey: .rsaSHA512(privateKey.publicKey))
        #if canImport(Darwin)
        case .secureEnclaveP256(let privateKey):
            return NIOSSHPublicKey(backingKey: .ecdsaP256(privateKey.publicKey))
        #endif
        }
    }
}

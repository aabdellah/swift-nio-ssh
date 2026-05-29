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

import XCTest

@testable import NIOSSH

final class CipherMACNegotiationTests: XCTestCase {
    // Advertised cipher list is de-duplicated, chacha first, in preference order.
    func testAdvertisedCiphersDeduplicatedAndOrdered() {
        let names = Constants.bundledTransportProtectionSchemes.map { $0.cipherName }
        // raw list contains aes*-ctr 4x each; the advertised list must collapse duplicates.
        let advertised = Self.dedup(names)
        XCTAssertEqual(advertised.first, "chacha20-poly1305@openssh.com")
        XCTAssertEqual(Set(advertised).count, advertised.count, "no duplicate cipher names")
        XCTAssertTrue(advertised.contains("aes256-ctr"))
        // Sanity: the raw list does carry duplicate ctr cipher names that dedup collapses.
        XCTAssertGreaterThan(names.count, advertised.count, "raw scheme list carries cipher-name duplicates")
    }

    // Every reachable (enc, mac) negotiation outcome resolves to a registered scheme.
    func testAsymmetricPreferenceResolvesToScheme() throws {
        // Peer prefers (aes256-ctr, hmac-sha2-256); we prefer the -etm variants.
        // Drive scheme resolution with these names and assert a concrete scheme is found.
        let scheme = try Self.resolveScheme(enc: "aes256-ctr", mac: "hmac-sha2-256")
        XCTAssertEqual(scheme.cipherName, "aes256-ctr")
        XCTAssertEqual(scheme.macName, "hmac-sha2-256")
        // chacha matches regardless of negotiated MAC (macName == nil arm).
        let chacha = try Self.resolveScheme(enc: "chacha20-poly1305@openssh.com", mac: "hmac-sha2-512")
        XCTAssertNil(chacha.macName)
    }

    // MARK: - Thin helpers mirroring SSHKeyExchangeStateMachine logic

    /// First-seen-order de-duplication — same shape as
    /// `SSHKeyExchangeStateMachine.supportedEncryptionAlgorithms`.
    static func dedup(_ names: [String]) -> [String] {
        var seen = Set<String>()
        return names.compactMap { seen.insert($0).inserted ? $0 : nil }
    }

    /// Scheme resolution — same predicate as the state machine's
    /// `negotiatedTransportProtection` -> scheme lookup:
    /// `cipherName == enc && (macName == nil || macName! == mac)`.
    static func resolveScheme(
        enc: String,
        mac: String
    ) throws -> (NIOSSHTransportProtection & _NIOSSHSendableMetatype).Type {
        guard
            let scheme = Constants.bundledTransportProtectionSchemes.first(where: {
                $0.cipherName == enc && ($0.macName == nil || $0.macName! == mac)
            })
        else {
            throw NIOSSHError.keyExchangeNegotiationFailure
        }
        return scheme
    }
}

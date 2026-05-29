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

import XCTest
import Crypto
@testable import NIOSSH

final class KeyDerivationExtensionTests: XCTestCase {
    // RFC 4253 §7.2: K1 = HASH(K‖H‖X‖sid); Kn = HASH(K‖H‖K1‖…‖K(n-1)); key = (K1‖K2‖…)[0..<len].
    // Reference values computed independently with SHA-256 (see Scripts/poly_kdf_ref.py in the commit msg).
    func testExtendsBeyondDigestSizeSHA256() {
        // Fixed inputs: K (mpint bytes), H, sessionID, discriminator 'C' (0x43).
        let baseInput: [UInt8] = Array(repeating: 0xAB, count: 40)   // stands in for K(mpint)‖H seed
        let sessionID: [UInt8] = Array(repeating: 0xCD, count: 32)
        let out = NIOSSHKeyDerivation.deriveForTest(
            seed: baseInput, discriminator: 0x43, sessionID: sessionID, length: 64, hash: SHA256.self)
        XCTAssertEqual(out.count, 64)
        // K1 = SHA256(seed‖0x43‖sid); K2 = SHA256(seed‖K1); key = (K1‖K2)[0..<64].
        var h1 = SHA256(); h1.update(data: baseInput); h1.update(data: [0x43]); h1.update(data: sessionID)
        let k1 = Array(h1.finalize())
        var h2 = SHA256(); h2.update(data: baseInput); h2.update(data: k1)
        let k2 = Array(h2.finalize())
        XCTAssertEqual(out, Array((k1 + k2).prefix(64)))
    }
}

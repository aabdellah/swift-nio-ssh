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
import NIOCore
@testable import NIOSSH

final class SSHCompressionTests: XCTestCase {
    func testSinglePacketRoundTrip() throws {
        let comp = try ZlibCompressor()
        let decomp = try ZlibDecompressor()
        let payload = ByteBuffer(string: "the quick brown fox jumps over the lazy dog")
        var compressed = try comp.compress(payload)
        let out = try decomp.decompress(&compressed, maxOutput: 64 * 1024)
        XCTAssertEqual(out, payload)
    }

    func testMultiPacketRetainsDictionary() throws {
        let comp = try ZlibCompressor()
        let decomp = try ZlibDecompressor()
        let p = ByteBuffer(string: String(repeating: "abcdefgh", count: 64))
        var c1 = try comp.compress(p)
        var c2 = try comp.compress(p)
        XCTAssertEqual(try decomp.decompress(&c1, maxOutput: 64 * 1024), p)
        XCTAssertEqual(try decomp.decompress(&c2, maxOutput: 64 * 1024), p)
        XCTAssertLessThan(c2.readableBytes, c1.readableBytes, "shared dictionary shrinks the repeat")
    }

    func testDecompressionBombGuard() throws {
        let comp = try ZlibCompressor()
        let decomp = try ZlibDecompressor()
        let big = ByteBuffer(repeating: 0, count: 256 * 1024)
        var compressed = try comp.compress(big)
        XCTAssertThrowsError(try decomp.decompress(&compressed, maxOutput: 64 * 1024)) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .protocolViolation)
        }
    }

    func testCompressionOfferReflectsFlag() {
        XCTAssertEqual(NIOSSHCompressionAlgorithm.disabledOffer, ["none"])
        XCTAssertEqual(NIOSSHCompressionAlgorithm.enabledOffer, ["zlib@openssh.com", "zlib", "none"])
    }
}

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
import XCTest

@testable import NIOSSH

final class ExtInfoTests: XCTestCase {
    func testExtInfoRoundTrips() throws {
        let message = SSHMessage.extInfo(.init(extensions: [
            .init(name: "server-sig-algs", value: "rsa-sha2-512,rsa-sha2-256,ssh-ed25519"),
            .init(name: "ext-foo", value: ""),
        ]))
        var buffer = ByteBufferAllocator().buffer(capacity: 256)
        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)
    }

    func testExtInfoEmptyRoundTrips() throws {
        let message = SSHMessage.extInfo(.init(extensions: []))
        var buffer = ByteBufferAllocator().buffer(capacity: 16)
        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(), message)
    }

    func testExtInfoOversizedCountRejected() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 16)
        buffer.writeInteger(SSHMessage.ExtInfoMessage.id)  // 7
        buffer.writeInteger(UInt32(100_000))  // absurd extension count
        // No actual extensions follow; a sane parser must reject, not allocate/spin.
        XCTAssertThrowsError(try buffer.readSSHMessage())
    }

    func testRSAVariantSelection() {
        // server prefers 512 → upgrade
        XCTAssertEqual(
            SSHMessage.UserAuthRequestMessage.preferredRSAIsSHA512(
                serverSignatureAlgorithms: ["rsa-sha2-512", "rsa-sha2-256"]),
            true)
        // server only offers 256 → 256
        XCTAssertEqual(
            SSHMessage.UserAuthRequestMessage.preferredRSAIsSHA512(
                serverSignatureAlgorithms: ["rsa-sha2-256"]),
            false)
        // no server-sig-algs → nil (conservative: keep the key's current variant)
        XCTAssertNil(
            SSHMessage.UserAuthRequestMessage.preferredRSAIsSHA512(serverSignatureAlgorithms: nil))
        // server offers neither RSA SHA-2 name → nil (conservative)
        XCTAssertNil(
            SSHMessage.UserAuthRequestMessage.preferredRSAIsSHA512(
                serverSignatureAlgorithms: ["ssh-ed25519"]))
    }
}

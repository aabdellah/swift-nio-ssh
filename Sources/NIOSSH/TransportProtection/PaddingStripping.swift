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

import Foundation

extension Data {
    /// Removes the SSH padding bytes from a decrypted packet body.
    ///
    /// The first byte of `self` is the padding length (which must be at least 4 per RFC 4253
    /// §6). The leading padding-length byte and the trailing padding bytes are sliced off,
    /// leaving the payload. Shared by the non-AEAD transport-protection schemes
    /// (chacha20-poly1305@openssh.com, AES-CTR) that decrypt a full plaintext body before
    /// stripping padding. Mirrors `AESGCM.swift`'s private `removePaddingBytes()`.
    mutating func removePaddingBytesChaCha() throws {
        guard let paddingLength = self.first, paddingLength >= 4 else {
            throw NIOSSHError.insufficientPadding
        }

        // Slice out the content bytes: the content begins after the padding-length byte and ends
        // `paddingLength` bytes before the end. If that walks off the front there is too much
        // padding for the available data.
        let contentStartIndex = self.index(after: self.startIndex)
        guard
            let contentEndIndex = self.index(
                self.endIndex, offsetBy: -Int(paddingLength), limitedBy: contentStartIndex)
        else {
            throw NIOSSHError.excessPadding
        }

        self = self[contentStartIndex..<contentEndIndex]
    }
}

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

/// A negotiated SSH transport compression algorithm. Names are the on-wire
/// compression algorithm names (RFC 4253 §6.2 + the OpenSSH delayed variant).
enum NIOSSHCompressionAlgorithm: Equatable {
    case none
    case zlib              // RFC 4253: active from the first NEWKEYS.
    case zlibDelayed       // zlib@openssh.com: active only after USERAUTH_SUCCESS.

    var wireName: Substring {
        switch self {
        case .none: return "none"
        case .zlib: return "zlib"
        case .zlibDelayed: return "zlib@openssh.com"
        }
    }

    init?(wireName: Substring) {
        switch wireName {
        case "none": self = .none
        case "zlib": self = .zlib
        case "zlib@openssh.com": self = .zlibDelayed
        default: return nil
        }
    }

    /// Locally-supported algorithms in preference order when compression is enabled.
    static let enabledOffer: [Substring] = ["zlib@openssh.com", "zlib", "none"]
    /// The advertised list when compression is disabled (byte-identical to today).
    static let disabledOffer: [Substring] = ["none"]
}

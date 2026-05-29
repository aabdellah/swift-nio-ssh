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

public enum Constants: Sendable {
    static let version = "SSH-2.0-SwiftNIOSSH_1.0"

    public static let bundledTransportProtectionSchemes: [(NIOSSHTransportProtection & _NIOSSHSendableMetatype).Type] =
        [
            ChaCha20Poly1305TransportProtection.self,
            AES256GCMOpenSSHTransportProtection.self, AES128GCMOpenSSHTransportProtection.self,
            // ETM before E&M, 256/192/128 by strength:
            AES256CTR_HMACSHA512ETM.self, AES256CTR_HMACSHA256ETM.self,
            AES192CTR_HMACSHA512ETM.self, AES192CTR_HMACSHA256ETM.self,
            AES128CTR_HMACSHA512ETM.self, AES128CTR_HMACSHA256ETM.self,
            AES256CTR_HMACSHA512.self, AES256CTR_HMACSHA256.self,
            AES192CTR_HMACSHA512.self, AES192CTR_HMACSHA256.self,
            AES128CTR_HMACSHA512.self, AES128CTR_HMACSHA256.self,
        ]
}

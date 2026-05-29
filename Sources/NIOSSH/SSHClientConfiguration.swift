//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2020 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIOCore

/// Configuration for an SSH client.
public struct SSHClientConfiguration {
    /// The user authentication delegate to be used with this client.
    public var userAuthDelegate: NIOSSHClientUserAuthenticationDelegate

    /// The server authentication delegate to be used with this client.
    public var serverAuthDelegate: NIOSSHClientServerAuthenticationDelegate

    /// The global request delegate to be used with this client.
    public var globalRequestDelegate: GlobalRequestDelegate

    /// Supported data encryption algorithms
    public var transportProtectionSchemes: [NIOSSHTransportProtection.Type]

    /// Whether to advertise and enable strict key exchange (Terrapin CVE-2023-48795 mitigation).
    /// When enabled, the client advertises `kex-strict-c-v00@openssh.com` in its KEX_INIT.
    /// If the server also advertises `kex-strict-s-v00@openssh.com`, strict KEX is activated,
    /// which resets sequence numbers after SSH_MSG_NEWKEYS to prevent prefix truncation attacks.
    /// Defaults to `true`.
    public var enableStrictKeyExchange: Bool

    /// Automatic rekey thresholds. When `dataBytes` is set, the client rekeys after
    /// that many transferred bytes since the last rekey; when `interval` is set, it
    /// rekeys that often. `nil` (the default) disables automatic rekeying.
    public var rekeyLimit: RekeyLimit?

    public struct RekeyLimit: Sendable, Equatable {
        public var dataBytes: UInt64?
        public var interval: TimeAmount?
        public init(dataBytes: UInt64? = nil, interval: TimeAmount? = nil) {
            self.dataBytes = dataBytes
            self.interval = interval
        }
    }

    public init(
        userAuthDelegate: NIOSSHClientUserAuthenticationDelegate,
        serverAuthDelegate: NIOSSHClientServerAuthenticationDelegate,
        globalRequestDelegate: GlobalRequestDelegate? = nil
    ) {
        self.init(
            userAuthDelegate: userAuthDelegate,
            serverAuthDelegate: serverAuthDelegate,
            globalRequestDelegate: globalRequestDelegate,
            transportProtectionSchemes: Constants.bundledTransportProtectionSchemes
        )
    }

    /// Restrict host-key algorithm negotiation to this ordered list.
    ///
    /// When non-nil and non-empty, the client advertises only these algorithms in
    /// its SSH_MSG_KEXINIT `server_host_key_algorithms` field. The server must
    /// advertise at least one algorithm from this list; if there is no overlap the
    /// connection fails with `NIOSSHError.keyExchangeNegotiationFailure`.
    ///
    /// Pass `nil` (the default) to use the library's built-in algorithm list, which
    /// is `ssh-ed25519`, the three ECDSA curves, then `rsa-sha2-512` and `rsa-sha2-256`
    /// (RSA SHA-2 host keys are verified by default). `ssh-rsa` (RFC 8332 legacy SHA-1)
    /// is NOT in the default set and is reachable only by listing it here explicitly;
    /// note that `ssh-rsa` signature *verification* is not currently implemented.
    ///
    /// Wire-format names: `"ssh-ed25519"`, `"ecdsa-sha2-nistp256"`,
    /// `"ecdsa-sha2-nistp384"`, `"ecdsa-sha2-nistp521"`,
    /// `"rsa-sha2-256"`, `"rsa-sha2-512"`, `"ssh-rsa"`.
    public var preferredHostKeyAlgorithms: [Substring]?

    public init(
        userAuthDelegate: NIOSSHClientUserAuthenticationDelegate,
        serverAuthDelegate: NIOSSHClientServerAuthenticationDelegate,
        globalRequestDelegate: GlobalRequestDelegate? = nil,
        transportProtectionSchemes: [NIOSSHTransportProtection.Type]
    ) {
        self.userAuthDelegate = userAuthDelegate
        self.serverAuthDelegate = serverAuthDelegate
        self.globalRequestDelegate = globalRequestDelegate ?? DefaultGlobalRequestDelegate()
        self.transportProtectionSchemes = transportProtectionSchemes
        self.enableStrictKeyExchange = true
        self.preferredHostKeyAlgorithms = nil
        self.rekeyLimit = nil
    }
}

// The various delegates aren't required to be Sendable, so the config isn't sendable.
@available(*, unavailable)
extension SSHClientConfiguration: Sendable {}

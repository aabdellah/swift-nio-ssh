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

/// Configuration for an SSH server.
public struct SSHServerConfiguration {
    /// The user authentication delegate to be used with this server.
    public var userAuthDelegate: NIOSSHServerUserAuthenticationDelegate

    /// The global request delegate to be used with this server.
    public var globalRequestDelegate: GlobalRequestDelegate

    /// The host keys for this server.
    public var hostKeys: [NIOSSHPrivateKey]

    /// The ssh banner to display to clients upon authentication
    public var banner: UserAuthBanner?

    /// Supported data encryption algorithms
    public var transportProtectionSchemes: [NIOSSHTransportProtection.Type]

    /// Whether to advertise and enable strict key exchange (Terrapin CVE-2023-48795 mitigation).
    /// When enabled, the server advertises `kex-strict-s-v00@openssh.com` in its KEX_INIT.
    /// If the client also advertises `kex-strict-c-v00@openssh.com`, strict KEX is activated,
    /// which resets sequence numbers after SSH_MSG_NEWKEYS to prevent prefix truncation attacks.
    /// Defaults to `true`.
    public var enableStrictKeyExchange: Bool

    public init(
        hostKeys: [NIOSSHPrivateKey],
        userAuthDelegate: NIOSSHServerUserAuthenticationDelegate,
        globalRequestDelegate: GlobalRequestDelegate? = nil,
        banner: UserAuthBanner? = nil
    ) {
        self.init(
            hostKeys: hostKeys,
            userAuthDelegate: userAuthDelegate,
            globalRequestDelegate: globalRequestDelegate,
            banner: banner,
            transportProtectionSchemes: Constants.bundledTransportProtectionSchemes
        )
    }

    public init(
        hostKeys: [NIOSSHPrivateKey],
        userAuthDelegate: NIOSSHServerUserAuthenticationDelegate,
        globalRequestDelegate: GlobalRequestDelegate? = nil
    ) {
        self.init(
            hostKeys: hostKeys,
            userAuthDelegate: userAuthDelegate,
            globalRequestDelegate: globalRequestDelegate,
            banner: nil
        )
    }

    public init(
        hostKeys: [NIOSSHPrivateKey],
        userAuthDelegate: NIOSSHServerUserAuthenticationDelegate,
        globalRequestDelegate: GlobalRequestDelegate? = nil,
        banner: UserAuthBanner? = nil,
        transportProtectionSchemes: [NIOSSHTransportProtection.Type]
    ) {
        self.hostKeys = hostKeys
        self.userAuthDelegate = userAuthDelegate
        self.globalRequestDelegate = globalRequestDelegate ?? DefaultGlobalRequestDelegate()
        self.banner = banner
        self.transportProtectionSchemes = transportProtectionSchemes
        self.enableStrictKeyExchange = true
    }
}

// The various delegates aren't required to be Sendable, so the config isn't sendable.
@available(*, unavailable)
extension SSHServerConfiguration: Sendable {}

// MARK: - UserAuthBanner

extension SSHServerConfiguration {
    /// A server sends a ``UserAuthBanner`` to the client at some point during authentication.
    /// A client is obligated to display this banner to the end user, unless explicitely told
    /// to ignore banners.
    public struct UserAuthBanner: Sendable {
        // The message to be displayed by the client to the end user during authentication.
        // Note that control characters contained in the message might be filtered by
        // the client in accordance with RFC 4252.
        public var message: String

        /// Tag describing the language used for message. Must obey RFC 3066
        public var languageTag: String

        public init(message: String, languageTag: String) {
            self.message = message
            self.languageTag = languageTag
        }
    }
}

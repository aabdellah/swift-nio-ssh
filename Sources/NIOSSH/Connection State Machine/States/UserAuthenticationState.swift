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

extension SSHConnectionStateMachine {
    /// The state of a state machine that is actively engaged in a user authentication operation.
    struct UserAuthenticationState {
        /// The role of the connection
        let role: SSHConnectionRole

        /// The packet parser.
        var parser: SSHPacketParser

        /// The packet serializer used by this state machine.
        var serializer: SSHPacketSerializer

        var remoteVersion: String

        var protectionSchemes: [NIOSSHTransportProtection.Type]

        var sessionIdentifier: ByteBuffer

        /// Whether strict KEX was negotiated on this connection's initial key exchange.
        /// Carried forward so re-keys can reset sequence numbers (the marker that drives
        /// this is only sent on the initial KEX). See `SSHKeyExchangeStateMachine`.
        let strictKexEnabled: Bool

        /// The backing state machine.
        var userAuthStateMachine: UserAuthenticationStateMachine

        init(sentNewKeysState state: SentNewKeysState) {
            self.role = state.role
            self.parser = state.parser
            self.serializer = state.serializer
            self.userAuthStateMachine = state.userAuthStateMachine
            self.remoteVersion = state.remoteVersion
            self.protectionSchemes = state.protectionSchemes
            self.sessionIdentifier = state.sessionIdentifier
            self.strictKexEnabled = state.keyExchangeStateMachine.strictKexEnabled
        }

        init(receivedNewKeysState state: ReceivedNewKeysState) {
            self.role = state.role
            self.parser = state.parser
            self.serializer = state.serializer
            self.userAuthStateMachine = state.userAuthStateMachine
            self.remoteVersion = state.remoteVersion
            self.protectionSchemes = state.protectionSchemes
            self.sessionIdentifier = state.sessionIdentifier
            self.strictKexEnabled = state.keyExchangeStateMachine.strictKexEnabled
        }

        mutating func bufferInboundData(_ data: inout ByteBuffer) {
            self.parser.append(bytes: &data)
        }

        /// Mirror the auth state machine's in-flight keyboard-interactive status onto the
        /// packet parser so that inbound message number 60 is disambiguated correctly.
        ///
        /// This MUST be kept in sync whenever the client sends a `SSH_MSG_USERAUTH_REQUEST`:
        /// disambiguating message 60 by the byte alone would silently corrupt password auth.
        mutating func syncKeyboardInteractiveExpectation() {
            self.parser.clientExpectingKeyboardInteractiveInfoRequest =
                self.userAuthStateMachine.clientInFlightMethodIsKeyboardInteractive
        }

        mutating func receiveExtInfo(_ message: SSHMessage.ExtInfoMessage) {
            for ext in message.extensions where ext.name == "server-sig-algs" {
                self.userAuthStateMachine.setServerSignatureAlgorithms(ext.value.split(separator: ","))
            }
        }
    }
}

extension SSHConnectionStateMachine.UserAuthenticationState: AcceptsUserAuthMessages {}

extension SSHConnectionStateMachine.UserAuthenticationState: SendsUserAuthMessages {}

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

/// A single prompt within an RFC 4256 keyboard-interactive `SSH_MSG_USERAUTH_INFO_REQUEST`.
public struct KeyboardInteractivePrompt: Hashable, Sendable {
    /// The text to display to the user.
    public let prompt: String

    /// Whether the user's typed response should be echoed.
    ///
    /// `false` indicates a secret (e.g. a password or OTP) and the response should be obscured.
    public let echo: Bool

    public init(prompt: String, echo: Bool) {
        self.prompt = prompt
        self.echo = echo
    }
}

/// An error indicating that a ``NIOSSHClientUserAuthenticationDelegate`` does not support
/// RFC 4256 keyboard-interactive authentication.
///
/// The default implementation of
/// ``NIOSSHClientUserAuthenticationDelegate/respondToKeyboardInteractiveChallenge(name:instruction:prompts:responsePromise:)``
/// fails the response promise with this error so that existing conformers continue to compile
/// and behave unchanged.
public struct NIOSSHKeyboardInteractiveUnsupportedError: Error, Hashable, Sendable {
    public init() {}
}

/// A ``NIOSSHClientUserAuthenticationDelegate`` is an object that can provide a sequence of
/// SSH user authentication methods based on the the acceptable list from the server.
///
/// This protocol defines the interface that will be used by the user authentication state
/// machine to move forward with challenges. Implementers of this protocol are free to take
/// time to actually get responses: for example, for password authentication it is possible
/// that the application would like to provide a user-interactive password prompt. This is
/// enabled by allowing implementers to satisfy a promise, rather than requiring that they
/// synchronously provide a response.
public protocol NIOSSHClientUserAuthenticationDelegate {
    /// Called when ``NIOSSH`` would like to attempt to offer a new authentication method.
    ///
    /// The callback is provided the authentication methods that the server is willing to accept in
    /// `availableMethods`. The delegate needs to provide an authentication offer by completing
    /// `nextChallengePromise`. If no further authentication offers are available (perhaps because the server
    /// has rejected them all) then this promise should be failed, which will terminate connection establishment.
    ///
    /// - parameters:
    ///     - availableMethods: The authentication methods the server is willing to accept.
    ///     - nextChallengePromise: An `EventLoopPromise` to be fulfilled with the next authentication offer.
    func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    )

    /// Called when the server reports a *partial* authentication success: the previous method
    /// was accepted, but the server requires one or more further methods before granting access
    /// (RFC 4252 §5.1, `SSH_MSG_USERAUTH_FAILURE` with `partial success = true`). This is the
    /// multi-factor (`AuthenticationMethods a,b`) continue signal.
    ///
    /// It is delivered immediately before the next ``nextAuthenticationType(availableMethods:nextChallengePromise:)``
    /// call for the new stage, so a delegate can reset any per-stage credential bookkeeping
    /// (the methods that satisfied the previous stage are spent; the next stage starts fresh).
    ///
    /// A default implementation is provided that does nothing, so existing conformers compile
    /// and behave unchanged.
    ///
    /// - parameter remainingMethods: The authentication methods the server will now accept for
    ///   the next stage.
    func partialAuthenticationSucceeded(remainingMethods: NIOSSHAvailableUserAuthenticationMethods)

    /// Called when the server issues an RFC 4256 keyboard-interactive
    /// `SSH_MSG_USERAUTH_INFO_REQUEST` and the delegate must supply responses.
    ///
    /// The state machine owns the multi-round loop: this method may be invoked more than once
    /// for a single keyboard-interactive offer, once per `INFO_REQUEST` round, until the server
    /// reports success or failure. The delegate must complete `responsePromise` with exactly
    /// one response string per prompt, in order. To abandon keyboard-interactive
    /// authentication, fail `responsePromise`; the auth attempt is then treated as a failure.
    ///
    /// A default implementation is provided that fails the promise with
    /// ``NIOSSHKeyboardInteractiveUnsupportedError``, so existing conformers compile unchanged.
    ///
    /// - parameters:
    ///     - name: The `name` field of the request (may be empty).
    ///     - instruction: The `instruction` field of the request (may be empty).
    ///     - prompts: The prompts to present to the user. May be empty, in which case the
    ///       state machine answers with an empty response without invoking this method.
    ///     - responsePromise: An `EventLoopPromise` to be fulfilled with one response per prompt.
    func respondToKeyboardInteractiveChallenge(
        name: String,
        instruction: String,
        prompts: [KeyboardInteractivePrompt],
        responsePromise: EventLoopPromise<[String]>
    )
}

extension NIOSSHClientUserAuthenticationDelegate {
    public func partialAuthenticationSucceeded(remainingMethods: NIOSSHAvailableUserAuthenticationMethods) {}

    public func respondToKeyboardInteractiveChallenge(
        name: String,
        instruction: String,
        prompts: [KeyboardInteractivePrompt],
        responsePromise: EventLoopPromise<[String]>
    ) {
        responsePromise.fail(NIOSSHKeyboardInteractiveUnsupportedError())
    }
}

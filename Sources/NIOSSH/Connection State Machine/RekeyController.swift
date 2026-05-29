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

import NIOCore

/// Tracks the data/time thresholds that drive a client-initiated rekey. Pure state;
/// the owning NIOSSHHandler performs the actual rekey + scheduling and consults the
/// state machine's `canRekey` guard. Counter is cumulative since the last rekey and
/// is NOT reset on NEWKEYS (unlike the packet sequence number).
struct RekeyController {
    private let dataBytes: UInt64?
    let interval: TimeAmount?
    private var bytesSinceRekey: UInt64 = 0

    /// The scheduled one-shot time-task, if any. Owned here so the handler can cancel
    /// it on teardown and reschedule on rekey.
    var scheduled: Scheduled<Void>?

    init(limit: SSHClientConfiguration.RekeyLimit) {
        self.dataBytes = limit.dataBytes
        self.interval = limit.interval
    }

    var hasInterval: Bool { self.interval != nil }

    /// Adds `count` transferred bytes; returns true if the data threshold is currently
    /// reached (level check — stays true until `reset()`).
    mutating func recordBytes(_ count: Int) -> Bool {
        guard let limit = self.dataBytes else { return false }
        self.bytesSinceRekey &+= UInt64(count)
        return self.bytesSinceRekey >= limit
    }

    /// Clears the byte counter (called when a rekey is initiated).
    mutating func reset() {
        self.bytesSinceRekey = 0
    }
}

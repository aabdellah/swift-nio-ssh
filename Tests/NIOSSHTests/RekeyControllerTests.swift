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
import XCTest

@testable import NIOSSH

final class RekeyControllerTests: XCTestCase {
    func testDataThresholdLevelCheck() {
        var c = RekeyController(limit: .init(dataBytes: 100, interval: nil))
        XCTAssertFalse(c.recordBytes(40))  // 40 < 100
        XCTAssertFalse(c.recordBytes(40))  // 80 < 100
        XCTAssertTrue(c.recordBytes(40))  // 120 >= 100 -> crossed
        XCTAssertTrue(c.recordBytes(0))  // still >= 100 (level, not edge)
    }

    func testResetClearsCounter() {
        var c = RekeyController(limit: .init(dataBytes: 100, interval: nil))
        _ = c.recordBytes(150)
        c.reset()
        XCTAssertFalse(c.recordBytes(10))  // counter back to 0 -> 10 < 100
    }

    func testNilDataBytesNeverCrosses() {
        var c = RekeyController(limit: .init(dataBytes: nil, interval: .seconds(1)))
        XCTAssertFalse(c.recordBytes(1_000_000))
    }

    func testHasIntervalReflectsConfig() {
        XCTAssertTrue(RekeyController(limit: .init(interval: .seconds(5))).hasInterval)
        XCTAssertFalse(RekeyController(limit: .init(dataBytes: 1)).hasInterval)
    }
}

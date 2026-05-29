import XCTest
@testable import NIOSSH

final class Poly1305Tests: XCTestCase {
    // RFC 8439 §2.5.2 worked example.
    func testRFC8439Section252() throws {
        let key: [UInt8] = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
            0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
            0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
            0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b,
        ]
        let message = Array("Cryptographic Forum Research Group".utf8)
        let expectedTag: [UInt8] = [
            0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6,
            0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9,
        ]
        var mac = Poly1305(key: key)
        mac.update(message)
        XCTAssertEqual(mac.finalize(), expectedTag)
    }

    // Empty message must still produce a valid tag (= s, reduced).
    func testEmptyMessage() {
        let key = [UInt8](repeating: 0, count: 32)
        var mac = Poly1305(key: key)
        mac.update([])
        XCTAssertEqual(mac.finalize(), [UInt8](repeating: 0, count: 16))
    }

    // Constant-time verify accepts the right tag and rejects a 1-bit flip.
    func testVerify() {
        let key = [UInt8](repeating: 7, count: 32)
        var mac = Poly1305(key: key); mac.update([1, 2, 3, 4]); let tag = mac.finalize()
        XCTAssertTrue(Poly1305.constantTimeEqual(tag, tag))
        var bad = tag; bad[0] ^= 0x01
        XCTAssertFalse(Poly1305.constantTimeEqual(tag, bad))
        XCTAssertFalse(Poly1305.constantTimeEqual(tag, Array(tag.prefix(15))))  // length mismatch
    }
}

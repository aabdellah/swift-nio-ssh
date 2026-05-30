import XCTest
import CZlib

final class CZlibLinkTests: XCTestCase {
    func testDeflateInflateRoundTrip() throws {
        let input = [UInt8]("hello hello hello hello hello".utf8)
        var deflated = [UInt8](repeating: 0, count: 256)

        var dStream = z_stream()
        XCTAssertEqual(deflateInit2_(&dStream, 6, Z_DEFLATED, 15, 8, Z_DEFAULT_STRATEGY,
                                     ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size)), Z_OK)
        var producedDeflate = 0
        input.withUnsafeBufferPointer { inBuf in
            dStream.next_in = UnsafeMutablePointer(mutating: inBuf.baseAddress)
            dStream.avail_in = UInt32(inBuf.count)
            deflated.withUnsafeMutableBufferPointer { outBuf in
                dStream.next_out = outBuf.baseAddress
                dStream.avail_out = UInt32(outBuf.count)
                _ = deflate(&dStream, Z_FINISH)
                producedDeflate = outBuf.count - Int(dStream.avail_out)
            }
        }
        _ = deflateEnd(&dStream)
        XCTAssertGreaterThan(producedDeflate, 0)

        var inflated = [UInt8](repeating: 0, count: 256)
        var iStream = z_stream()
        XCTAssertEqual(inflateInit2_(&iStream, 15, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size)), Z_OK)
        var producedInflate = 0
        deflated.withUnsafeMutableBufferPointer { inBuf in
            iStream.next_in = inBuf.baseAddress
            iStream.avail_in = UInt32(producedDeflate)
            inflated.withUnsafeMutableBufferPointer { outBuf in
                iStream.next_out = outBuf.baseAddress
                iStream.avail_out = UInt32(outBuf.count)
                _ = inflate(&iStream, Z_FINISH)
                producedInflate = outBuf.count - Int(iStream.avail_out)
            }
        }
        _ = inflateEnd(&iStream)
        XCTAssertEqual(Array(inflated.prefix(producedInflate)), input)
    }
}

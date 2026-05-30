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

import CZlib
import NIOCore

/// Persistent outbound deflate stream. One instance per connection-direction;
/// the deflate dictionary accumulates across packets and is flushed per packet
/// with Z_PARTIAL_FLUSH so each packet is independently decodable by the peer.
final class ZlibCompressor {
    private var stream = z_stream()

    init() throws {
        let status = deflateInit2_(
            &stream,
            6,                  // compression level
            Z_DEFLATED,
            15,                 // windowBits
            8,                  // memLevel
            Z_DEFAULT_STRATEGY,
            ZLIB_VERSION,
            Int32(MemoryLayout<z_stream>.size)
        )
        guard status == Z_OK else {
            throw NIOSSHError.protocolViolation(
                protocolName: "compression",
                violation: "deflateInit \(status)"
            )
        }
    }

    deinit { _ = deflateEnd(&stream) }

    /// Compress one SSH packet payload. The deflate dictionary is retained
    /// across calls; each call emits a Z_PARTIAL_FLUSH boundary so the peer
    /// can decode this packet immediately.
    func compress(_ payload: ByteBuffer) throws -> ByteBuffer {
        // Allocate an output buffer. deflateBound gives the maximum possible
        // size for a single-shot Z_FINISH; for Z_PARTIAL_FLUSH the output may
        // be slightly larger because of the flush marker overhead — but in
        // practice deflateBound is a safe upper bound for small-to-medium
        // payloads. We use a 4 KB minimum so empty-ish inputs still work.
        let inputCount = payload.readableBytes
        let outputCapacity = max(Int(deflateBound(&stream, UInt(inputCount))) + 12, 4096)

        var output = ByteBufferAllocator().buffer(capacity: outputCapacity)

        try payload.withUnsafeReadableBytes { inputPtr in
            // Handle empty input: zlib still needs non-nil pointers.
            let baseInput: UnsafeMutablePointer<UInt8>
            if inputCount == 0 {
                // Use a scratch byte so next_in is non-nil.
                var scratch: UInt8 = 0
                baseInput = withUnsafeMutablePointer(to: &scratch) { $0 }
            } else {
                baseInput = UnsafeMutablePointer(mutating: inputPtr.baseAddress!.assumingMemoryBound(to: UInt8.self))
            }

            stream.next_in = baseInput
            stream.avail_in = UInt32(inputCount)

            // Drive deflate until avail_out > 0 after a call, which means
            // the codec has emitted all pending output for this flush boundary.
            repeat {
                let written = try output.writeWithUnsafeMutableBytes(minimumWritableBytes: 4096) { outPtr -> Int in
                    stream.next_out = outPtr.baseAddress!.assumingMemoryBound(to: UInt8.self)
                    stream.avail_out = UInt32(outPtr.count)

                    let rc = deflate(&stream, Z_PARTIAL_FLUSH)
                    guard rc == Z_OK || rc == Z_BUF_ERROR else {
                        throw NIOSSHError.protocolViolation(
                            protocolName: "compression",
                            violation: "deflate returned \(rc)"
                        )
                    }

                    return outPtr.count - Int(stream.avail_out)
                }
                _ = written  // output already advanced inside writeWithUnsafeMutableBytes
            } while stream.avail_out == 0
        }

        return output
    }
}

/// Persistent inbound inflate stream with a per-packet output cap
/// (decompression-bomb guard).
final class ZlibDecompressor {
    private var stream = z_stream()

    init() throws {
        let status = inflateInit2_(
            &stream,
            15,                 // windowBits
            ZLIB_VERSION,
            Int32(MemoryLayout<z_stream>.size)
        )
        guard status == Z_OK else {
            throw NIOSSHError.protocolViolation(
                protocolName: "compression",
                violation: "inflateInit \(status)"
            )
        }
    }

    deinit { _ = inflateEnd(&stream) }

    /// Decompress one SSH packet payload. Throws `protocolViolation` if the
    /// decompressed output would exceed `maxOutput` bytes (bomb guard) or if
    /// the zlib stream signals a hard error.
    func decompress(_ payload: inout ByteBuffer, maxOutput: Int) throws -> ByteBuffer {
        let inputCount = payload.readableBytes
        var output = ByteBufferAllocator().buffer(capacity: min(inputCount * 4, maxOutput))

        try payload.withUnsafeReadableBytes { inputPtr in
            let baseInput: UnsafeMutablePointer<UInt8>
            if inputCount == 0 {
                var scratch: UInt8 = 0
                baseInput = withUnsafeMutablePointer(to: &scratch) { $0 }
            } else {
                baseInput = UnsafeMutablePointer(mutating: inputPtr.baseAddress!.assumingMemoryBound(to: UInt8.self))
            }

            stream.next_in = baseInput
            stream.avail_in = UInt32(inputCount)

            var done = false
            while !done {
                // Bomb guard: check before growing the output further.
                if output.readableBytes > maxOutput {
                    throw NIOSSHError.protocolViolation(
                        protocolName: "compression",
                        violation: "decompressed output exceeded maxOutput (\(maxOutput) bytes)"
                    )
                }

                let chunkSize = 4096
                let written = try output.writeWithUnsafeMutableBytes(minimumWritableBytes: chunkSize) { outPtr -> Int in
                    stream.next_out = outPtr.baseAddress!.assumingMemoryBound(to: UInt8.self)
                    stream.avail_out = UInt32(outPtr.count)

                    let rc = inflate(&stream, Z_SYNC_FLUSH)

                    switch rc {
                    case Z_OK, Z_STREAM_END:
                        // Normal: some (possibly zero) output was produced.
                        let produced = outPtr.count - Int(stream.avail_out)
                        if rc == Z_STREAM_END {
                            done = true
                        }
                        return produced

                    case Z_BUF_ERROR:
                        // No progress — no input and no output available: we're done
                        // for this packet.
                        done = true
                        return 0

                    default:
                        throw NIOSSHError.protocolViolation(
                            protocolName: "compression",
                            violation: "inflate returned \(rc)"
                        )
                    }
                }
                _ = written

                // If inflate consumed all input and produced nothing new, we're done.
                if stream.avail_in == 0 && stream.avail_out > 0 {
                    done = true
                }

                // Bomb guard after each chunk.
                if output.readableBytes > maxOutput {
                    throw NIOSSHError.protocolViolation(
                        protocolName: "compression",
                        violation: "decompressed output exceeded maxOutput (\(maxOutput) bytes)"
                    )
                }
            }
        }

        return output
    }
}

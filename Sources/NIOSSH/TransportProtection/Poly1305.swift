import Foundation

/// RFC 8439 §2.5 Poly1305 one-time authenticator — clean-room from the RFC.
///
/// NOT derived from poly1305-donna/ref10 or any third-party source. The accumulator
/// `h` is held in three 64-bit limbs (little-endian; value < 2^131 between blocks).
/// Multiplication uses `UInt64.multipliedFullWidth(by:)` for the 64×64→128 partial
/// products, and the reduction uses the identity 2^130 ≡ 5 (mod 2^130 − 5). All
/// operations are data-independent (constant-time). Correctness is gated by the
/// RFC 8439 §2.5.2 golden vector in `Poly1305Tests` — if that fails, the bug is in
/// the limb arithmetic here; iterate until green, do not weaken the test.
///
/// Note: this uses 64-bit `(high, low)` limb pairs rather than `UInt128`. The
/// stdlib `UInt128` type's `BinaryInteger`/`FixedWidthInteger` conformances are
/// only backdeployed to macOS 15 / iOS 18, but NIOSSH targets macOS 10.15 / iOS 13.
/// `multipliedFullWidth(by:)` and `addingReportingOverflow(_:)` are available on
/// all those targets and give the identical 128-bit results.
struct Poly1305 {
    private var h0: UInt64 = 0
    private var h1: UInt64 = 0
    private var h2: UInt64 = 0      // only the low ~3 bits are populated after each reduce
    private let r0: UInt64          // clamped, < 2^60
    private let r1: UInt64          // clamped, < 2^60
    private let s0: UInt64
    private let s1: UInt64

    init(key: [UInt8]) {
        precondition(key.count == 32, "Poly1305 one-time key is 32 bytes")
        func le64(_ s: ArraySlice<UInt8>) -> UInt64 {
            var v: UInt64 = 0
            var i = 0
            for b in s { v |= UInt64(b) << (8 * i); i += 1 }
            return v
        }
        // r = key[0..16] little-endian, clamped (RFC 8439 mask 0x0ffffffc0ffffffc0ffffffc0fffffff).
        self.r0 = le64(key[0..<8]) & 0x0FFF_FFFC_0FFF_FFFF
        self.r1 = le64(key[8..<16]) & 0x0FFF_FFFC_0FFF_FFFC
        self.s0 = le64(key[16..<24])
        self.s1 = le64(key[24..<32])
    }

    // MARK: - 128-bit helpers (high:low UInt64 pairs)

    /// 64×64 → 128. Returns (high, low).
    @inline(__always)
    private static func mul(_ a: UInt64, _ b: UInt64) -> (high: UInt64, low: UInt64) {
        let (hi, lo) = a.multipliedFullWidth(by: b)
        return (hi, lo)
    }

    /// 128 + 128 → 128 (wrapping; high bits beyond 128 discarded, callers stay < 2^128).
    @inline(__always)
    private static func add(_ a: (high: UInt64, low: UInt64), _ b: (high: UInt64, low: UInt64)) -> (high: UInt64, low: UInt64) {
        let (lo, c) = a.low.addingReportingOverflow(b.low)
        let hi = a.high &+ b.high &+ (c ? 1 : 0)
        return (hi, lo)
    }

    mutating func update<M: Collection>(_ message: M) where M.Element == UInt8 {
        var block = [UInt8](repeating: 0, count: 16)
        var it = message.makeIterator()
        while true {
            for i in 0..<16 { block[i] = 0 }
            var n = 0
            while n < 16, let b = it.next() { block[n] = b; n += 1 }
            if n == 0 { break }                     // message exhausted on a block boundary
            let hibit: UInt64 = (n == 16) ? 1 : 0   // full block adds 2^128
            if n < 16 { block[n] = 1 }              // partial block: append a single 1 byte
            addBlock(block, hibit: hibit)
            multiplyByR()
            if n < 16 { break }
        }
    }

    private mutating func addBlock(_ block: [UInt8], hibit: UInt64) {
        func le64(_ off: Int) -> UInt64 {
            var v: UInt64 = 0
            for i in 0..<8 { v |= UInt64(block[off + i]) << (8 * i) }
            return v
        }
        let n0 = le64(0), n1 = le64(8)
        let (x0, c0) = h0.addingReportingOverflow(n0)
        h0 = x0
        let (x1, c1) = h1.addingReportingOverflow(n1)
        let (x1b, c1b) = x1.addingReportingOverflow(c0 ? 1 : 0)
        h1 = x1b
        h2 = h2 &+ hibit &+ (c1 ? 1 : 0) &+ (c1b ? 1 : 0)
    }

    private mutating func multiplyByR() {
        // Schoolbook product h*r into 64-bit limbs t0..t4 (base B = 2^64). h_i < 2^64 (h2 small),
        // r_i < 2^60, so each partial fits in 128 bits without overflow.
        let d0 = Poly1305.mul(h0, r0)
        let d1 = Poly1305.add(Poly1305.mul(h0, r1), Poly1305.mul(h1, r0))
        let d2 = Poly1305.add(Poly1305.mul(h1, r1), Poly1305.mul(h2, r0))
        let d3 = Poly1305.mul(h2, r1)

        // Fold carries up the limb chain. m_k = d_k + (m_{k-1} >> 64); t_k = low(m_k).
        let t0 = d0.low
        let m1 = Poly1305.add(d1, (high: 0, low: d0.high)); let t1 = m1.low
        let m2 = Poly1305.add(d2, (high: 0, low: m1.high)); let t2 = m2.low
        let m3 = Poly1305.add(d3, (high: 0, low: m2.high)); let t3 = m3.low
        let t4 = m3.high

        // Reduce mod 2^130 − 5. V = t0 + t1·B + t2·B² + t3·B³ + t4·B⁴ < 2^255.
        // lo = V mod 2^130 (t0, t1, low 2 bits of t2). hi = V >> 130 = (t2,t3,t4) >> 2, hi < 2^125.
        let lo0 = t0, lo1 = t1, lo2 = t2 & 0x3
        let hi0 = (t2 >> 2) | (t3 << 62)
        let hi1 = (t3 >> 2) | (t4 << 62)
        let hi2 = t4 >> 2
        // value = lo + 5*hi  (5*hi < 2^128, so result < 2^131).
        let f0 = Poly1305.mul(hi0, 5)
        let f1 = Poly1305.add(Poly1305.mul(hi1, 5), (high: 0, low: f0.high))
        let f2 = Poly1305.add(Poly1305.mul(hi2, 5), (high: 0, low: f1.high))
        let a0 = Poly1305.add((high: 0, low: lo0), (high: 0, low: f0.low))
        let a1 = Poly1305.add(Poly1305.add((high: 0, low: lo1), (high: 0, low: f1.low)), (high: 0, low: a0.high))
        let a2 = Poly1305.add(Poly1305.add((high: 0, low: lo2), (high: 0, low: f2.low)), (high: 0, low: a1.high))
        h0 = a0.low
        h1 = a1.low
        h2 = a2.low   // < 2^3
    }

    func finalize() -> [UInt8] {
        // One more fold so h < 2^130+small, then a constant-time conditional subtract of p.
        var x0 = h0, x1 = h1, x2 = h2
        let top = x2 >> 2; x2 &= 0x3
        let e0 = Poly1305.add((high: 0, low: x0), Poly1305.mul(top, 5))
        x0 = e0.low
        let e1 = Poly1305.add((high: 0, low: x1), (high: 0, low: e0.high))
        x1 = e1.low
        x2 = x2 &+ e1.high

        // h - p = h + 5 - 2^130. If h >= p, then (h+5) has bit 130 set; clearing it yields h - p.
        let (g0, b0) = x0.addingReportingOverflow(5)
        let (g1, b1) = x1.addingReportingOverflow(b0 ? 1 : 0)
        let g2 = x2 &+ (b1 ? 1 : 0)
        let ge = (g2 >> 2) & 1                    // 1 iff h >= p
        let mask = ~(ge &- 1)                     // all-ones iff ge == 1, else 0 (constant-time select)
        let r0sel = (g0 & mask) | (x0 & ~mask)
        let r1sel = (g1 & mask) | (x1 & ~mask)

        // tag = (h + s) mod 2^128, little-endian.
        let a0 = Poly1305.add((high: 0, low: r0sel), (high: 0, low: s0))
        let a1 = Poly1305.add(Poly1305.add((high: 0, low: r1sel), (high: 0, low: s1)), (high: 0, low: a0.high))
        let lo = a0.low
        let hi = a1.low
        var out = [UInt8](repeating: 0, count: 16)
        for i in 0..<8 { out[i] = UInt8((lo >> (8 * i)) & 0xff) }
        for i in 0..<8 { out[8 + i] = UInt8((hi >> (8 * i)) & 0xff) }
        return out
    }

    /// Constant-time tag comparison (`Crypto.safeCompare` is module-internal, so hand-rolled).
    static func constantTimeEqual(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        guard a.count == b.count else { return false }
        var diff: UInt8 = 0
        for i in 0..<a.count { diff |= a[i] ^ b[i] }
        return diff == 0
    }
}

@testable import GMSwift

/// 测试用的简单任意精度无符号整数（32位字，小端），只用来校验优化后的运算，速度无关紧要。
struct ReferenceBigInt: Equatable, Comparable {
    private(set) var words: [UInt32]

    init(_ words: [UInt32]) {
        var trimmed = words
        while trimmed.last == 0 {
            trimmed.removeLast()
        }
        self.words = trimmed
    }

    init(_ value: BigInt256) {
        self.init(ReferenceBigInt.split([value.l0, value.l1, value.l2, value.l3]))
    }

    init(_ value: Wide512) {
        self.init(ReferenceBigInt.split([value.0, value.1, value.2, value.3, value.4, value.5, value.6, value.7]))
    }

    private static func split(_ limbs: [UInt64]) -> [UInt32] {
        return limbs.flatMap { [UInt32(truncatingIfNeeded: $0), UInt32($0 >> 32)] }
    }

    var bigInt256: BigInt256 {
        precondition(words.count <= 8)
        let padded = words + [UInt32](repeating: 0, count: 8 - words.count)
        func limb(_ index: Int) -> UInt64 {
            return UInt64(padded[index * 2]) | UInt64(padded[index * 2 + 1]) << 32
        }
        return BigInt256(limb(0), limb(1), limb(2), limb(3))
    }

    static func < (lhs: ReferenceBigInt, rhs: ReferenceBigInt) -> Bool {
        if lhs.words.count != rhs.words.count {
            return lhs.words.count < rhs.words.count
        }
        for index in stride(from: lhs.words.count - 1, through: 0, by: -1) where lhs.words[index] != rhs.words[index] {
            return lhs.words[index] < rhs.words[index]
        }
        return false
    }

    static func + (lhs: ReferenceBigInt, rhs: ReferenceBigInt) -> ReferenceBigInt {
        var result = [UInt32]()
        var carry: UInt64 = 0
        for index in 0..<max(lhs.words.count, rhs.words.count) {
            let a = index < lhs.words.count ? UInt64(lhs.words[index]) : 0
            let b = index < rhs.words.count ? UInt64(rhs.words[index]) : 0
            let sum = a + b + carry
            result.append(UInt32(truncatingIfNeeded: sum))
            carry = sum >> 32
        }
        result.append(UInt32(carry))
        return ReferenceBigInt(result)
    }

    /// 要求 lhs >= rhs
    static func - (lhs: ReferenceBigInt, rhs: ReferenceBigInt) -> ReferenceBigInt {
        precondition(lhs >= rhs)
        var result = [UInt32]()
        var borrow: Int64 = 0
        for index in 0..<lhs.words.count {
            let b = index < rhs.words.count ? Int64(rhs.words[index]) : 0
            var difference = Int64(lhs.words[index]) - b - borrow
            borrow = difference < 0 ? 1 : 0
            if difference < 0 {
                difference += 1 << 32
            }
            result.append(UInt32(difference))
        }
        return ReferenceBigInt(result)
    }

    static func * (lhs: ReferenceBigInt, rhs: ReferenceBigInt) -> ReferenceBigInt {
        var result = [UInt32](repeating: 0, count: lhs.words.count + rhs.words.count + 1)
        for (i, a) in lhs.words.enumerated() {
            var carry: UInt64 = 0
            for (j, b) in rhs.words.enumerated() {
                let value = UInt64(a) * UInt64(b) + UInt64(result[i + j]) + carry
                result[i + j] = UInt32(truncatingIfNeeded: value)
                carry = value >> 32
            }
            result[i + rhs.words.count] = UInt32(carry)
        }
        return ReferenceBigInt(result)
    }

    /// 逐位移位相减
    static func % (lhs: ReferenceBigInt, modulus: ReferenceBigInt) -> ReferenceBigInt {
        var remainder = ReferenceBigInt([])
        for word in lhs.words.reversed() {
            for bit in stride(from: 31, through: 0, by: -1) {
                remainder = remainder + remainder + ReferenceBigInt([(word >> UInt32(bit)) & 1])
                if remainder >= modulus {
                    remainder = remainder - modulus
                }
            }
        }
        return remainder
    }

    func power(_ exponent: BigInt256, modulus: ReferenceBigInt) -> ReferenceBigInt {
        var result = ReferenceBigInt([1]) % modulus
        for bit in stride(from: exponent.bitLength - 1, through: 0, by: -1) {
            result = (result * result) % modulus
            if exponent.getBit(bit) {
                result = (result * self) % modulus
            }
        }
        return result
    }
}

/// 确定性伪随机数（xorshift64），失败可复现
struct TestRandom {
    private var state: UInt64

    init(seed: UInt64) {
        state = seed
    }

    mutating func next() -> UInt64 {
        state ^= state << 13
        state ^= state >> 7
        state ^= state << 17
        return state
    }

    mutating func bigInt() -> BigInt256 {
        return BigInt256(next(), next(), next(), next())
    }

    mutating func bytes(_ count: Int) -> [UInt8] {
        return (0..<count).map { _ in UInt8(truncatingIfNeeded: next() >> 24) }
    }
}

enum EdgeValues {
    static let p = SM2Curve.p
    static let n = SM2Curve.n

    /// 0, 1, p-1, n-1, p, n, 2^256-1 以及迫使最大进位的模式
    static let all: [BigInt256] = [
        .zero, .one, BigInt256(2, 0, 0, 0), p, p.sub(.one).0, p.add(.one).0, n, n.sub(.one).0, n.add(.one).0,
        BigInt256(.max, .max, .max, .max),
        BigInt256(.max, 0, 0, 0), BigInt256(0, .max, 0, 0), BigInt256(0, 0, .max, 0), BigInt256(0, 0, 0, .max),
        BigInt256(.max, .max, 0, 0), BigInt256(0, 0, .max, .max), BigInt256(0, .max, .max, 0),
        BigInt256(0, 0, 0, 1 << 63), BigInt256(1 << 63, 1 << 63, 1 << 63, 1 << 63),
        BigInt256(0xFFFF_FFFF_0000_0000, 0xFFFF_FFFF_0000_0000, 0xFFFF_FFFF_0000_0000, 0xFFFF_FFFF_0000_0000),
        BigInt256(0x0000_0000_FFFF_FFFF, 0x0000_0000_FFFF_FFFF, 0x0000_0000_FFFF_FFFF, 0x0000_0000_FFFF_FFFF),
    ]
}

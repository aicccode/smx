// SM9（GB/T 38635）的素数域 Fq 与曲线阶 N 上的运算。
//
// q 是一般的256位素数，没有可利用的特殊形式，所以 Fq 和 N 都用 Montgomery 乘法（R = 2^256），
// 4个 UInt64 limb（BigInt256），全部用掩码实现，不含按数据分支。Fq 元素内部一律是 Montgomery 形式，
// 只在编解码时转换。

// MARK: - 曲线参数

enum SM9Params {
    /// 基域特征 q
    @inline(__always)
    static var q: BigInt256 {
        return BigInt256(0xE56F_9B27_E351_457D, 0x21F2_934B_1A7A_EEDB, 0xD603_AB4F_F58E_C745, 0xB640_0000_02A3_A6F1)
    }

    /// 群的阶 N
    @inline(__always)
    static var n: BigInt256 {
        return BigInt256(0xE56E_E19C_D69E_CF25, 0x49F2_934B_18EA_8BEE, 0xD603_AB4F_F58E_C744, 0xB640_0000_02A3_A6F1)
    }

    /// N - 1
    @inline(__always)
    static var nMinus1: BigInt256 {
        return BigInt256(0xE56E_E19C_D69E_CF24, 0x49F2_934B_18EA_8BEE, 0xD603_AB4F_F58E_C744, 0xB640_0000_02A3_A6F1)
    }

    /// BN 参数 t
    static let t: UInt64 = 0x6000_0000_0058_F98A

    /// 6t^2 = q - N，G2 上 Frobenius 的特征值（子群检查用）
    @inline(__always)
    static var sixTSquared: BigInt256 {
        return BigInt256(0x0000_B98B_0CB2_7658, 0xD800_0000_0190_62ED, 0, 0)
    }

    /// -q^(-1) mod 2^64
    static let q0Inverse: UInt64 = 0x892B_C42C_2F2E_E42B
    /// -N^(-1) mod 2^64
    static let n0Inverse: UInt64 = 0x1D02_6623_5197_4B53

    /// R mod q（Montgomery 形式的 1）
    @inline(__always)
    static var qR: BigInt256 {
        return BigInt256(0x1A90_64D8_1CAE_BA83, 0xDE0D_6CB4_E585_1124, 0x29FC_54B0_0A71_38BA, 0x49BF_FFFF_FD5C_590E)
    }

    /// R^2 mod q
    @inline(__always)
    static var qR2: BigInt256 {
        return BigInt256(0x27DE_A312_B417_E2D2, 0x88F8_105F_AE1A_5D3F, 0xE479_B522_D670_6E7B, 0x2EA7_95A6_56F6_2FBD)
    }

    /// R^2 mod N
    @inline(__always)
    static var nR2: BigInt256 {
        return BigInt256(0x7598_CD79_CD75_0C35, 0xE4A0_8110_BB6D_AEAB, 0xBFEE_4BAE_7D78_A1F9, 0x8894_F5D1_6369_5D0E)
    }
}

// MARK: - 通用 Montgomery 约减

/// 一轮约减：消去 a0，结果落在 a1...a4，溢出累计到 carry
@inline(__always)
private func sm9ReduceStep(
    _ a0: UInt64, _ a1: inout UInt64, _ a2: inout UInt64, _ a3: inout UInt64, _ a4: inout UInt64,
    _ carry: inout UInt64, _ m: BigInt256, _ m0Inverse: UInt64
) {
    let k = a0 &* m0Inverse
    var row = multiplyAdd(k, m.l0, a0, 0)
    row = multiplyAdd(k, m.l1, a1, row.high)
    a1 = row.low
    row = multiplyAdd(k, m.l2, a2, row.high)
    a2 = row.low
    row = multiplyAdd(k, m.l3, a3, row.high)
    a3 = row.low
    var overflow = carry
    a4 = addWithCarry(a4, row.high, &overflow)
    carry = overflow
}

/// value / 2^256 mod m。value < m * 2^256 时结果在 [0, m) 内（m 是奇数，最高位为 1 时也正确：溢出位单独记录）。
@inline(__always)
func sm9MontgomeryReduce(_ value: Wide512, _ m: BigInt256, _ m0Inverse: UInt64) -> BigInt256 {
    var (t1, t2, t3, t4, t5, t6, t7) = (value.1, value.2, value.3, value.4, value.5, value.6, value.7)
    var carry: UInt64 = 0
    sm9ReduceStep(value.0, &t1, &t2, &t3, &t4, &carry, m, m0Inverse)
    sm9ReduceStep(t1, &t2, &t3, &t4, &t5, &carry, m, m0Inverse)
    sm9ReduceStep(t2, &t3, &t4, &t5, &t6, &carry, m, m0Inverse)
    sm9ReduceStep(t3, &t4, &t5, &t6, &t7, &carry, m, m0Inverse)
    let result = BigInt256(t4, t5, t6, t7)
    let (reduced, borrow) = result.subtractingWithBorrow(m)
    return BigInt256.select((0 &- carry) | zeroMask(borrow), reduced, result)
}

// 加减法的条件修正：LLVM 曾把“借位时加上 q & mask”编译成按借位跳转（跳过加载 q 的常量），
// 在秘密标量乘法和 GT 幂运算里就是依赖秘密数据的分支。掩码都经过 opaqueMask，优化器无法得知它只取 0 或全 1。

/// (a + b) mod m，a、b < m
@inline(__always)
func sm9ModAdd(_ a: BigInt256, _ b: BigInt256, _ m: BigInt256) -> BigInt256 {
    let (sum, carry) = a.addingWithCarry(b)
    let (reduced, borrow) = sum.subtractingWithBorrow(m)
    return BigInt256.select(opaqueMask((0 &- carry) | zeroMask(borrow)), reduced, sum)
}

/// (a - b) mod m，a、b < m
@inline(__always)
func sm9ModSub(_ a: BigInt256, _ b: BigInt256, _ m: BigInt256) -> BigInt256 {
    let (difference, borrow) = a.subtractingWithBorrow(b)
    let mask = opaqueMask(0 &- borrow)
    var carry: UInt64 = 0
    let r0 = addWithCarry(difference.l0, m.l0 & mask, &carry)
    let r1 = addWithCarry(difference.l1, m.l1 & mask, &carry)
    let r2 = addWithCarry(difference.l2, m.l2 & mask, &carry)
    let r3 = addWithCarry(difference.l3, m.l3 & mask, &carry)
    return BigInt256(r0, r1, r2, r3)
}

// MARK: - Fq 元素（Montgomery 形式）

struct SM9Fp {
    /// Montgomery 形式 a * R mod q，总在 [0, q) 内
    var m: BigInt256

    @inline(__always)
    init(montgomery: BigInt256) {
        m = montgomery
    }

    /// 由规范表示（必须小于 q）构造
    @inline(__always)
    init(canonical value: BigInt256) {
        m = sm9MontgomeryReduce(value.mul(SM9Params.qR2), SM9Params.q, SM9Params.q0Inverse)
    }

    @inline(__always)
    init(small value: UInt64) {
        self.init(canonical: BigInt256(value, 0, 0, 0))
    }

    @inline(__always)
    static var zero: SM9Fp { return SM9Fp(montgomery: .zero) }

    @inline(__always)
    static var one: SM9Fp { return SM9Fp(montgomery: SM9Params.qR) }

    /// 规范表示
    @inline(__always)
    var canonical: BigInt256 {
        return sm9MontgomeryReduce((m.l0, m.l1, m.l2, m.l3, 0, 0, 0, 0), SM9Params.q, SM9Params.q0Inverse)
    }

    @inline(__always)
    var isZeroMask: UInt64 { return m.isZeroMask }

    @inline(__always)
    var isZero: Bool { return m.isZero }

    @inline(__always)
    static func == (lhs: SM9Fp, rhs: SM9Fp) -> Bool {
        return lhs.m == rhs.m
    }

    @inline(__always)
    static func equalMask(_ a: SM9Fp, _ b: SM9Fp) -> UInt64 {
        return BigInt256.equalMask(a.m, b.m)
    }

    @inline(__always)
    static func select(_ mask: UInt64, _ a: SM9Fp, _ b: SM9Fp) -> SM9Fp {
        return SM9Fp(montgomery: BigInt256.select(mask, a.m, b.m))
    }

    @inline(__always)
    func add(_ other: SM9Fp) -> SM9Fp {
        return SM9Fp(montgomery: sm9ModAdd(m, other.m, SM9Params.q))
    }

    @inline(__always)
    func sub(_ other: SM9Fp) -> SM9Fp {
        return SM9Fp(montgomery: sm9ModSub(m, other.m, SM9Params.q))
    }

    @inline(__always)
    func double() -> SM9Fp {
        return add(self)
    }

    @inline(__always)
    func neg() -> SM9Fp {
        return SM9Fp(montgomery: sm9ModSub(.zero, m, SM9Params.q))
    }

    @inline(__always)
    func mul(_ other: SM9Fp) -> SM9Fp {
        return SM9Fp(montgomery: sm9MontgomeryReduce(m.mul(other.m), SM9Params.q, SM9Params.q0Inverse))
    }

    @inline(__always)
    func square() -> SM9Fp {
        return SM9Fp(montgomery: sm9MontgomeryReduce(m.square(), SM9Params.q, SM9Params.q0Inverse))
    }

    /// 费马小定理求逆 a^(q-2)，0 的结果是 0。指数是公开常量，固定4位窗口，查表下标只取决于指数。
    func inverse() -> SM9Fp {
        let exponent = SM9Params.q.subtractingWithBorrow(BigInt256(2, 0, 0, 0)).difference
        var table = [SM9Fp](repeating: .one, count: 16)
        table[1] = self
        for index in 2..<16 {
            table[index] = table[index - 1].mul(self)
        }
        var result = table[Int(truncatingIfNeeded: exponent.l3 &>> 60)]
        for position in stride(from: 248, through: 0, by: -4) {
            result = result.square().square().square().square()
            let window = Int(truncatingIfNeeded: exponent.bits(from: position) & 0xF)
            if window != 0 {
                result = result.mul(table[window])
            }
        }
        return result
    }

    /// 32字节大端
    func writeBE(to output: UnsafeMutablePointer<UInt8>) {
        canonical.writeBE(to: output)
    }

    func toBEBytes() -> [UInt8] {
        return canonical.toBEBytes()
    }
}

// MARK: - 模 N 的标量运算

enum SM9Scalar {
    /// 1 <= k <= N-1 时返回全 1，否则 0。不按 k 的值分支。
    @inline(__always)
    static func validMask(_ k: BigInt256) -> UInt64 {
        let below = 0 &- k.subtractingWithBorrow(SM9Params.n).borrow
        return below & ~k.isZeroMask
    }

    @inline(__always)
    static func add(_ a: BigInt256, _ b: BigInt256) -> BigInt256 {
        return sm9ModAdd(a, b, SM9Params.n)
    }

    @inline(__always)
    static func sub(_ a: BigInt256, _ b: BigInt256) -> BigInt256 {
        return sm9ModSub(a, b, SM9Params.n)
    }

    @inline(__always)
    private static func montMul(_ a: BigInt256, _ b: BigInt256) -> BigInt256 {
        return sm9MontgomeryReduce(a.mul(b), SM9Params.n, SM9Params.n0Inverse)
    }

    /// a * b mod N，a、b < N
    static func mul(_ a: BigInt256, _ b: BigInt256) -> BigInt256 {
        return montMul(montMul(a, b), SM9Params.nR2)
    }

    /// a^(N-2) mod N（a = 0 时得到 0）。指数公开，固定4位窗口。
    static func inverse(_ a: BigInt256) -> BigInt256 {
        let exponent = SM9Params.n.subtractingWithBorrow(BigInt256(2, 0, 0, 0)).difference
        let base = montMul(a, SM9Params.nR2)
        var table = [BigInt256](repeating: base, count: 16)
        for index in 2..<16 {
            table[index] = montMul(table[index - 1], base)
        }
        var result = table[Int(truncatingIfNeeded: exponent.l3 &>> 60)]
        for position in stride(from: 248, through: 0, by: -4) {
            for _ in 0..<4 {
                result = montMul(result, result)
            }
            let window = Int(truncatingIfNeeded: exponent.bits(from: position) & 0xF)
            if window != 0 {
                result = montMul(result, table[window])
            }
        }
        secureWipe(&table)
        return montMul(result, BigInt256.one)
    }

    /// (hi * 2^256 + lo) mod (N - 1)，hi < 2^64。逐位移位、掩码相减，不按数据分支（输入可能来自秘密值的哈希）。
    static func reduceModNMinus1(high: UInt64, low: BigInt256) -> BigInt256 {
        let modulus = SM9Params.nMinus1
        var remainder = BigInt256.zero
        for bit in stride(from: 319, through: 0, by: -1) {
            let incoming = bit >= 256 ? (high &>> UInt64(bit - 256)) & 1 : (low.bits(from: bit) & 1)
            let overflow = remainder.l3 &>> 63
            remainder = BigInt256(
                (remainder.l0 &<< 1) | incoming,
                (remainder.l1 &<< 1) | (remainder.l0 &>> 63),
                (remainder.l2 &<< 1) | (remainder.l1 &>> 63),
                (remainder.l3 &<< 1) | (remainder.l2 &>> 63)
            )
            let (reduced, borrow) = remainder.subtractingWithBorrow(modulus)
            // 溢出（真实值 >= 2^256 > m）或不小于 m 时取差
            remainder = BigInt256.select(opaqueMask((0 &- overflow) | zeroMask(borrow)), reduced, remainder)
        }
        return remainder
    }
}

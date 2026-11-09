// SM9 的扩域塔（与 GB/T 38635.5 第2章相同）：
//   Fq2  = Fq[u]  / (u^2 + 2)
//   Fq4  = Fq2[v] / (v^2 - u)
//   Fq12 = Fq4[w] / (w^3 - v)，所以 w^6 = u
// 全部运算由 SM9Fp 的无分支运算组成；select 用掩码。

// MARK: - Fq2

struct SM9Fp2 {
    var c0: SM9Fp
    var c1: SM9Fp

    @inline(__always)
    init(_ c0: SM9Fp, _ c1: SM9Fp) {
        self.c0 = c0
        self.c1 = c1
    }

    @inline(__always)
    static var zero: SM9Fp2 { return SM9Fp2(.zero, .zero) }

    @inline(__always)
    static var one: SM9Fp2 { return SM9Fp2(.one, .zero) }

    @inline(__always)
    var isZeroMask: UInt64 { return c0.isZeroMask & c1.isZeroMask }

    @inline(__always)
    var isZero: Bool { return (c0.m.l0 | c0.m.l1 | c0.m.l2 | c0.m.l3 | c1.m.l0 | c1.m.l1 | c1.m.l2 | c1.m.l3) == 0 }

    @inline(__always)
    static func == (lhs: SM9Fp2, rhs: SM9Fp2) -> Bool {
        return lhs.c0 == rhs.c0 && lhs.c1 == rhs.c1
    }

    @inline(__always)
    static func select(_ mask: UInt64, _ a: SM9Fp2, _ b: SM9Fp2) -> SM9Fp2 {
        return SM9Fp2(SM9Fp.select(mask, a.c0, b.c0), SM9Fp.select(mask, a.c1, b.c1))
    }

    @inline(__always)
    func add(_ o: SM9Fp2) -> SM9Fp2 { return SM9Fp2(c0.add(o.c0), c1.add(o.c1)) }

    @inline(__always)
    func sub(_ o: SM9Fp2) -> SM9Fp2 { return SM9Fp2(c0.sub(o.c0), c1.sub(o.c1)) }

    @inline(__always)
    func double() -> SM9Fp2 { return SM9Fp2(c0.double(), c1.double()) }

    @inline(__always)
    func neg() -> SM9Fp2 { return SM9Fp2(c0.neg(), c1.neg()) }

    /// 共轭，也就是 q 次 Frobenius
    @inline(__always)
    func conjugate() -> SM9Fp2 { return SM9Fp2(c0, c1.neg()) }

    /// (a0 + a1 u)(b0 + b1 u) = a0 b0 - 2 a1 b1 + (a0 b1 + a1 b0) u，Karatsuba 3次乘法
    @inline(__always)
    func mul(_ o: SM9Fp2) -> SM9Fp2 {
        let v0 = c0.mul(o.c0)
        let v1 = c1.mul(o.c1)
        let cross = c0.add(c1).mul(o.c0.add(o.c1)).sub(v0).sub(v1)
        return SM9Fp2(v0.sub(v1.double()), cross)
    }

    /// (a0 + a1 u)^2 = (a0 + a1)(a0 - 2 a1) + a0 a1 + 2 a0 a1 u，2次乘法
    @inline(__always)
    func square() -> SM9Fp2 {
        let product = c0.mul(c1)
        let real = c0.add(c1).mul(c0.sub(c1.double())).add(product)
        return SM9Fp2(real, product.double())
    }

    @inline(__always)
    func mulFp(_ k: SM9Fp) -> SM9Fp2 { return SM9Fp2(c0.mul(k), c1.mul(k)) }

    /// 乘 u：(a0 + a1 u) u = -2 a1 + a0 u
    @inline(__always)
    func mulU() -> SM9Fp2 { return SM9Fp2(c1.double().neg(), c0) }

    /// 1/(a0 + a1 u) = (a0 - a1 u) / (a0^2 + 2 a1^2)，0 的结果是 0
    func inverse() -> SM9Fp2 {
        let norm = c0.square().add(c1.square().double())
        let inv = norm.inverse()
        return SM9Fp2(c0.mul(inv), c1.mul(inv).neg())
    }
}

// MARK: - Fq4

struct SM9Fp4 {
    var c0: SM9Fp2
    var c1: SM9Fp2

    @inline(__always)
    init(_ c0: SM9Fp2, _ c1: SM9Fp2) {
        self.c0 = c0
        self.c1 = c1
    }

    @inline(__always)
    static var zero: SM9Fp4 { return SM9Fp4(.zero, .zero) }

    @inline(__always)
    static var one: SM9Fp4 { return SM9Fp4(.one, .zero) }

    @inline(__always)
    static func == (lhs: SM9Fp4, rhs: SM9Fp4) -> Bool {
        return lhs.c0 == rhs.c0 && lhs.c1 == rhs.c1
    }

    @inline(__always)
    static func select(_ mask: UInt64, _ a: SM9Fp4, _ b: SM9Fp4) -> SM9Fp4 {
        return SM9Fp4(SM9Fp2.select(mask, a.c0, b.c0), SM9Fp2.select(mask, a.c1, b.c1))
    }

    @inline(__always)
    func add(_ o: SM9Fp4) -> SM9Fp4 { return SM9Fp4(c0.add(o.c0), c1.add(o.c1)) }

    @inline(__always)
    func sub(_ o: SM9Fp4) -> SM9Fp4 { return SM9Fp4(c0.sub(o.c0), c1.sub(o.c1)) }

    @inline(__always)
    func double() -> SM9Fp4 { return SM9Fp4(c0.double(), c1.double()) }

    @inline(__always)
    func neg() -> SM9Fp4 { return SM9Fp4(c0.neg(), c1.neg()) }

    /// Fq4 对 Fq2 的共轭 v -> -v（即 q^2 次 Frobenius）
    @inline(__always)
    func conjugate() -> SM9Fp4 { return SM9Fp4(c0, c1.neg()) }

    /// Karatsuba：v0 + u v1 + ((a0 + a1)(b0 + b1) - v0 - v1) v
    @inline(__always)
    func mul(_ o: SM9Fp4) -> SM9Fp4 {
        let v0 = c0.mul(o.c0)
        let v1 = c1.mul(o.c1)
        let cross = c0.add(c1).mul(o.c0.add(o.c1)).sub(v0).sub(v1)
        return SM9Fp4(v0.add(v1.mulU()), cross)
    }

    /// (a0 + a1 v)^2 = a0^2 + u a1^2 + ((a0 + a1)^2 - a0^2 - a1^2) v，3次 Fq2 平方
    @inline(__always)
    func square() -> SM9Fp4 {
        let s0 = c0.square()
        let s1 = c1.square()
        let cross = c0.add(c1).square().sub(s0).sub(s1)
        return SM9Fp4(s0.add(s1.mulU()), cross)
    }

    /// 乘以 Fq2 元素
    @inline(__always)
    func mulFp2(_ k: SM9Fp2) -> SM9Fp4 { return SM9Fp4(c0.mul(k), c1.mul(k)) }

    /// 乘 v：(a0 + a1 v) v = a1 u + a0 v
    @inline(__always)
    func mulV() -> SM9Fp4 { return SM9Fp4(c1.mulU(), c0) }

    /// 1/(a0 + a1 v) = (a0 - a1 v) / (a0^2 - u a1^2)
    func inverse() -> SM9Fp4 {
        let norm = c0.square().sub(c1.square().mulU())
        let inv = norm.inverse()
        return SM9Fp4(c0.mul(inv), c1.mul(inv).neg())
    }
}

// MARK: - Fq12

/// Frobenius 常量 gamma_k^j = u^(j (q^k - 1) / 6)（k = 1, 2, 3；j = 1...5），全部落在 Fq 内，Montgomery 形式。
private enum SM9FrobeniusConstants {
    @inline(__always)
    private static func fp(_ l0: UInt64, _ l1: UInt64, _ l2: UInt64, _ l3: UInt64) -> SM9Fp {
        return SM9Fp(montgomery: BigInt256(l0, l1, l2, l3))
    }

    static let gamma1: [SM9Fp] = [
        fp(0x1A98_DFBD_4575_299F, 0x9EC8_547B_245C_54FD, 0xF51F_5EAC_13DF_846C, 0x9EF7_4015_D5A1_6393),
        fp(0xB626_197D_CE47_36CA, 0x0829_6B35_57ED_0186, 0x9C70_5DB2_FD91_512A, 0x1C75_3E74_8601_C992),
        fp(0x39B4_EF0F_3EE7_2529, 0xDB04_3BF5_0858_2782, 0xB855_4AB0_54AC_91E3, 0x9848_EEC2_5498_CAB5),
        fp(0x8105_4FCD_94E9_C1C4, 0x4C0E_91CB_8CE2_DF3E, 0x4877_B452_E8AE_DFB4, 0x88F5_3E74_8B49_1776),
        fp(0x048B_AA79_DCC3_4107, 0x5E2E_7AC4_FE76_C161, 0x9939_9754_365B_D4BC, 0xAF91_AEAC_819B_0E13),
    ]

    static let gamma2: [SM9Fp] = [
        fp(0xB626_197D_CE47_36CA, 0x0829_6B35_57ED_0186, 0x9C70_5DB2_FD91_512A, 0x1C75_3E74_8601_C992),
        fp(0x8105_4FCD_94E9_C1C4, 0x4C0E_91CB_8CE2_DF3E, 0x4877_B452_E8AE_DFB4, 0x88F5_3E74_8B49_1776),
        fp(0xCADF_364F_C6A2_8AFA, 0x43E5_2696_34F5_DDB7, 0xAC07_569F_EB1D_8E8A, 0x6C80_0000_0547_4DE3),
        fp(0x2F49_81AA_150A_0EB3, 0x19C9_2815_C28D_ED55, 0x3993_4D9C_F7FD_761B, 0x99CA_C18B_7CA1_DD5F),
        fp(0x646A_4B5A_4E67_83B9, 0xD5E4_017F_8D98_0F9D, 0x8D8B_F6FD_0CDF_E790, 0x2D4A_C18B_775A_8F7B),
    ]

    static let gamma3: [SM9Fp] = [
        fp(0x39B4_EF0F_3EE7_2529, 0xDB04_3BF5_0858_2782, 0xB855_4AB0_54AC_91E3, 0x9848_EEC2_5498_CAB5),
        fp(0xCADF_364F_C6A2_8AFA, 0x43E5_2696_34F5_DDB7, 0xAC07_569F_EB1D_8E8A, 0x6C80_0000_0547_4DE3),
        fp(0xABBA_AC18_A46A_2054, 0x46EE_5756_1222_C759, 0x1DAE_609F_A0E2_3561, 0x1DF7_113D_AE0A_DC3C),
        fp(0x1A90_64D8_1CAE_BA83, 0xDE0D_6CB4_E585_1124, 0x29FC_54B0_0A71_38BA, 0x49BF_FFFF_FD5C_590E),
        fp(0x39B4_EF0F_3EE7_2529, 0xDB04_3BF5_0858_2782, 0xB855_4AB0_54AC_91E3, 0x9848_EEC2_5498_CAB5),
    ]
}

/// c0 + c1 w + c2 w^2。按 w 的幂看是6个 Fq2 系数 x_k：c_i = x_i + x_{i+3} v。
struct SM9Fp12 {
    var c0: SM9Fp4
    var c1: SM9Fp4
    var c2: SM9Fp4

    @inline(__always)
    init(_ c0: SM9Fp4, _ c1: SM9Fp4, _ c2: SM9Fp4) {
        self.c0 = c0
        self.c1 = c1
        self.c2 = c2
    }

    @inline(__always)
    static var zero: SM9Fp12 { return SM9Fp12(.zero, .zero, .zero) }

    @inline(__always)
    static var one: SM9Fp12 { return SM9Fp12(.one, .zero, .zero) }

    static func == (lhs: SM9Fp12, rhs: SM9Fp12) -> Bool {
        return lhs.c0 == rhs.c0 && lhs.c1 == rhs.c1 && lhs.c2 == rhs.c2
    }

    var isOne: Bool { return self == SM9Fp12.one }

    @inline(__always)
    static func select(_ mask: UInt64, _ a: SM9Fp12, _ b: SM9Fp12) -> SM9Fp12 {
        return SM9Fp12(SM9Fp4.select(mask, a.c0, b.c0), SM9Fp4.select(mask, a.c1, b.c1), SM9Fp4.select(mask, a.c2, b.c2))
    }

    /// Karatsuba 三项乘法，6次 Fq4 乘法
    func mul(_ o: SM9Fp12) -> SM9Fp12 {
        let v0 = c0.mul(o.c0)
        let v1 = c1.mul(o.c1)
        let v2 = c2.mul(o.c2)
        let t0 = c1.add(c2).mul(o.c1.add(o.c2)).sub(v1).sub(v2).mulV().add(v0)
        let t1 = c0.add(c1).mul(o.c0.add(o.c1)).sub(v0).sub(v1).add(v2.mulV())
        let t2 = c0.add(c2).mul(o.c0.add(o.c2)).sub(v0).sub(v2).add(v1)
        return SM9Fp12(t0, t1, t2)
    }

    /// Chung-Hasan SQR2
    func square() -> SM9Fp12 {
        let s0 = c0.square()
        let s1 = c1.mul(c2).double()
        let s2 = c0.sub(c1).add(c2).square()
        let s3 = c0.mul(c1).double()
        let s4 = c2.square()
        return SM9Fp12(s0.add(s1.mulV()), s3.add(s4.mulV()), s1.add(s2).add(s3).sub(s0).sub(s4))
    }

    /// 乘以 Miller 循环的稀疏线函数 a + c w^2，a ∈ Fq4，c ∈ Fq2：
    /// (f0 a + v f1 c) + (f1 a + v f2 c) w + (f2 a + f0 c) w^2
    @inline(__always)
    func mulLine(_ a: SM9Fp4, _ c: SM9Fp2) -> SM9Fp12 {
        let f0a = c0.mul(a)
        let f1a = c1.mul(a)
        let f2a = c2.mul(a)
        return SM9Fp12(
            f0a.add(c1.mulFp2(c).mulV()),
            f1a.add(c2.mulFp2(c).mulV()),
            f2a.add(c0.mulFp2(c))
        )
    }

    /// Granger-Scott 分圆子群平方，只对阶整除 q^4 - q^2 + 1 的元素（最终幂的简单部分之后）成立：
    /// (3a^2 - 2 conj(a)) + (3 v c^2 + 2 conj(b)) w + (3 b^2 - 2 conj(c)) w^2
    @inline(__always)
    func cyclotomicSquare() -> SM9Fp12 {
        let a2 = c0.square()
        let b2 = c1.square()
        let cv = c2.square().mulV()
        let r0 = a2.sub(c0.conjugate()).double().add(a2)
        let r1 = cv.add(c1.conjugate()).double().add(cv)
        let r2 = b2.sub(c2.conjugate()).double().add(b2)
        return SM9Fp12(r0, r1, r2)
    }

    /// x^(q^6)：w -> -w，Fq2 系数不变。分圆子群内就是求逆。
    @inline(__always)
    func conjugate() -> SM9Fp12 {
        return SM9Fp12(c0.conjugate(), c1.conjugate().neg(), c2.conjugate())
    }

    /// x^(q^k)，k = 1, 2, 3：x_j -> conj^k(x_j) * gamma_k^j
    func frobenius(_ k: Int) -> SM9Fp12 {
        let gamma: [SM9Fp]
        switch k {
        case 1: gamma = SM9FrobeniusConstants.gamma1
        case 2: gamma = SM9FrobeniusConstants.gamma2
        default: gamma = SM9FrobeniusConstants.gamma3
        }
        let odd = k % 2 == 1
        @inline(__always)
        func map(_ x: SM9Fp2) -> SM9Fp2 { return odd ? x.conjugate() : x }
        let x0 = map(c0.c0)
        let x1 = map(c1.c0).mulFp(gamma[0])
        let x2 = map(c2.c0).mulFp(gamma[1])
        let x3 = map(c0.c1).mulFp(gamma[2])
        let x4 = map(c1.c1).mulFp(gamma[3])
        let x5 = map(c2.c1).mulFp(gamma[4])
        return SM9Fp12(SM9Fp4(x0, x3), SM9Fp4(x1, x4), SM9Fp4(x2, x5))
    }

    /// 一般求逆（三次扩张的伴随矩阵公式），0 的结果是 0
    func inverse() -> SM9Fp12 {
        let t0 = c0.square().sub(c1.mul(c2).mulV())
        let t1 = c2.square().mulV().sub(c0.mul(c1))
        let t2 = c1.square().sub(c0.mul(c2))
        let norm = c0.mul(t0).add(c2.mul(t1).add(c1.mul(t2)).mulV())
        let inv = norm.inverse()
        return SM9Fp12(t0.mul(inv), t1.mul(inv), t2.mul(inv))
    }

    /// 平方-乘法求幂，可变时间，只用于公开指数（测试和公开的 t）
    func powPublic(_ exponent: BigInt256) -> SM9Fp12 {
        var result = SM9Fp12.one
        let bits = exponent.bitLength
        var index = bits - 1
        while index >= 0 {
            result = result.square()
            if exponent.getBit(index) {
                result = result.mul(self)
            }
            index -= 1
        }
        return result
    }

    /// 384字节：c2 || c1 || c0，每个 Fq4 c = a + b v 写成 b || a，每个 Fq2 写成 a1 || a0
    func toBytes() -> [UInt8] {
        var out = [UInt8](repeating: 0, count: 384)
        out.withUnsafeMutableBufferPointer { buffer in
            guard let base = buffer.baseAddress else {
                return
            }
            let parts = [c2.c1, c2.c0, c1.c1, c1.c0, c0.c1, c0.c0]
            for (index, coefficient) in parts.enumerated() {
                coefficient.c1.writeBE(to: base + index * 64)
                coefficient.c0.writeBE(to: base + index * 64 + 32)
            }
        }
        return out
    }
}

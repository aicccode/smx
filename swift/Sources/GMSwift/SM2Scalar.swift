// 曲线阶 n 上的算术：Montgomery 约减（R = 2^256），全部用掩码实现，不含按数据分支。
// 对外只暴露规范表示，Montgomery 形式仅在内部使用。

enum ScalarField {
    /// -n^(-1) mod 2^64
    private static let n0Inverse: UInt64 = 0x327F_9E88_7235_0975

    /// R^2 mod n
    @inline(__always)
    private static var rSquared: BigInt256 {
        return BigInt256(0x9011_92AF_7C11_4F20, 0x3464_504A_DE6F_A2FA, 0x620F_C84C_3AFF_E0D4, 0x1EB5_E412_A22B_3D3B)
    }

    /// 一轮约减：消去 a0，结果落在 a1...a4，溢出累计到 carry
    @inline(__always)
    private static func reduceStep(
        _ a0: UInt64, _ a1: inout UInt64, _ a2: inout UInt64, _ a3: inout UInt64, _ a4: inout UInt64,
        _ carry: inout UInt64
    ) {
        let n = SM2Curve.n
        let q = a0 &* n0Inverse
        var row = multiplyAdd(q, n.l0, a0, 0)
        row = multiplyAdd(q, n.l1, a1, row.high)
        a1 = row.low
        row = multiplyAdd(q, n.l2, a2, row.high)
        a2 = row.low
        row = multiplyAdd(q, n.l3, a3, row.high)
        a3 = row.low
        var overflow = carry
        a4 = addWithCarry(a4, row.high, &overflow)
        carry = overflow
    }

    /// Montgomery 约减：返回 value / R mod n。对任意512位输入结果都小于 2^256（但可能不小于 n）；
    /// 当 value < 2^256 * n 时结果一定小于 n。
    @inline(__always)
    private static func montgomeryReduce(_ value: Wide512) -> BigInt256 {
        var (t1, t2, t3, t4, t5, t6, t7) = (value.1, value.2, value.3, value.4, value.5, value.6, value.7)
        var carry: UInt64 = 0
        reduceStep(value.0, &t1, &t2, &t3, &t4, &carry)
        reduceStep(t1, &t2, &t3, &t4, &t5, &carry)
        reduceStep(t2, &t3, &t4, &t5, &t6, &carry)
        reduceStep(t3, &t4, &t5, &t6, &t7, &carry)

        let result = BigInt256(t4, t5, t6, t7)
        let (reduced, borrow) = result.subtractingWithBorrow(SM2Curve.n)
        return BigInt256.select((0 &- carry) | zeroMask(borrow), reduced, result)
    }

    @inline(never)
    private static func montgomeryMultiply(_ a: BigInt256, _ b: BigInt256) -> BigInt256 {
        return montgomeryReduce(a.mul(b))
    }

    @inline(never)
    private static func montgomerySquare(_ a: BigInt256) -> BigInt256 {
        return montgomeryReduce(a.square())
    }

    /// 任意512位值 mod n
    static func reduce(_ value: Wide512) -> BigInt256 {
        // value / R 再乘 R^2 / R，第二次的输入小于 2^256 * n，结果落在 [0, n)
        return montgomeryMultiply(montgomeryReduce(value), rSquared)
    }

    /// 费马小定理求逆：a^(n-2) mod n。指数是公开常量，用固定4位窗口；
    /// 窗口下标由公开指数决定，所以查表不泄露 a。
    static func invert(_ a: BigInt256) -> BigInt256 {
        let exponent = SM2Curve.n.subtractingWithBorrow(BigInt256(2, 0, 0, 0)).difference
        let base = montgomeryMultiply(a, rSquared)
        return withUnsafeTemporaryAllocation(of: BigInt256.self, capacity: 16) { table -> BigInt256 in
            table[1] = base
            for index in 2..<16 {
                table[index] = montgomeryMultiply(table[index - 1], base)
            }
            var result = table[Int(truncatingIfNeeded: exponent.l3 &>> 60)]
            for position in stride(from: 248, through: 0, by: -4) {
                result = montgomerySquare(result)
                result = montgomerySquare(result)
                result = montgomerySquare(result)
                result = montgomerySquare(result)
                let window = Int(truncatingIfNeeded: exponent.bits(from: position) & 0xF)
                if window != 0 {
                    result = montgomeryMultiply(result, table[window])
                }
            }
            return montgomeryReduce((result.l0, result.l1, result.l2, result.l3, 0, 0, 0, 0))
        }
    }
}

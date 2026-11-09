// SM9 的 R-ate 对（GB/T 38635.1 B.6.2）：a = 6t + 2，Miller 循环里 T 用 Jacobian 坐标（无求逆），
// 线函数在 P 处求值并按稀疏形式相乘，最后 T += pi(Q)、T -= pi^2(Q)，再做最终幂 (q^12 - 1)/N。
//
// 线函数乘了 Fq2 中的因子（Jacobian 坐标的分母），最终幂会把真子域的元素消去，所以结果与 sm9_ref.py 完全一致。
// 循环用 6t+2 的 NAF（减法步多出的竖线也在 Fq6 里，同样被消去）。
// 循环的步骤只取决于公开常量；Q 可以是秘密点（解密、密钥交换里的用户私钥），运算本身不含按数据分支。
// 对阶为 N 的 Q，循环中 T 不会等于 ±Q、±pi(Q)，加法公式没有特殊情况。

import Foundation

enum SM9Pairing {
    /// 6t+2 的 NAF，最高位在前（66位）
    private static let loopDigits: [Int8] = [
        1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 1, 0, 0, 0, 1, 0, -1, 0, -1, 0, 0, 0, -1, 0, -1, 0, 0, 1, 0, 1, 0, 0, 0, 0, -1, 0,
    ]

    /// 倍点步：返回线函数 (a, c)，线 = a + c w^2，同时把 T 更新为 2T。
    /// 线 = (2Y^2 - 3X^3) + (-2 Y Z^3 yP) v + (3 X^2 Z^2 xP) w^2，即切线乘以 2 Y Z^3。
    @inline(__always)
    private static func doublingStep(
        _ t: inout SM9G2, xP: SM9Fp, negYP: SM9Fp
    ) -> (SM9Fp4, SM9Fp2) {
        let a = t.x.square()
        let b = t.y.square()
        let c = b.square()
        let d = t.x.add(b).square().sub(a).sub(c).double()
        let e = a.double().add(a)
        let f = e.square()
        let zz = t.z.square()
        let x3 = f.sub(d.double())
        let y3 = e.mul(d.sub(x3)).sub(c.double().double().double())
        let z3 = t.y.add(t.z).square().sub(b).sub(zz)
        let l0 = b.double().sub(e.mul(t.x))
        let l3 = z3.mul(zz).mulFp(negYP)
        let l2 = e.mul(zz).mulFp(xP)
        t = SM9G2(x: x3, y: y3, z: z3)
        return (SM9Fp4(l0, l3), l2)
    }

    /// 加法步（Q 仿射）：线 = (Z3 yQ - r xQ) + (-Z3 yP) v + (r xP) w^2，即经过 T、Q 的直线乘以 Z3。
    @inline(__always)
    private static func additionStep(
        _ t: inout SM9G2, _ q: SM9Affine<SM9Fp2>, xP: SM9Fp, negYP: SM9Fp
    ) -> (SM9Fp4, SM9Fp2) {
        let z1z1 = t.z.square()
        let u2 = q.x.mul(z1z1)
        let s2 = q.y.mul(t.z).mul(z1z1)
        let h = u2.sub(t.x)
        let r = s2.sub(t.y)
        let hh = h.square()
        let hhh = h.mul(hh)
        let v = t.x.mul(hh)
        let x3 = r.square().sub(hhh).sub(v.double())
        let y3 = r.mul(v.sub(x3)).sub(t.y.mul(hhh))
        let z3 = t.z.mul(h)
        let l0 = z3.mul(q.y).sub(r.mul(q.x))
        let l3 = z3.mulFp(negYP)
        let l2 = r.mulFp(xP)
        t = SM9G2(x: x3, y: y3, z: z3)
        return (SM9Fp4(l0, l3), l2)
    }

    /// Miller 循环 f_{a,Q}(P) 乘上两次 Frobenius 修正，未做最终幂
    static func millerLoop(_ p: SM9Affine<SM9Fp>, _ q: SM9Affine<SM9Fp2>) -> SM9Fp12 {
        let xP = p.x
        let negYP = p.y.neg()
        let negQ = q.negated()
        var t = q.jacobian
        var f = SM9Fp12.one
        var first = true
        for digit in loopDigits.dropFirst() {
            let (a, c) = doublingStep(&t, xP: xP, negYP: negYP)
            if first {
                // f = 1：1^2 * line 就是线函数本身
                f = SM9Fp12(a, .zero, SM9Fp4(c, .zero))
                first = false
            } else {
                f = f.square().mulLine(a, c)
            }
            if digit == 1 {
                let (a, c) = additionStep(&t, q, xP: xP, negYP: negYP)
                f = f.mulLine(a, c)
            } else if digit == -1 {
                let (a, c) = additionStep(&t, negQ, xP: xP, negYP: negYP)
                f = f.mulLine(a, c)
            }
        }
        let q1 = SM9Points.frobenius(q)
        let q2 = SM9Points.frobenius(q1)
        var (a, c) = additionStep(&t, q1, xP: xP, negYP: negYP)
        f = f.mulLine(a, c)
        (a, c) = additionStep(&t, q2.negated(), xP: xP, negYP: negYP)
        return f.mulLine(a, c)
    }

    /// f^t（t 公开且为正），分圆平方
    @inline(__always)
    private static func powT(_ f: SM9Fp12) -> SM9Fp12 {
        var result = f
        var bit = 62  // t 的最高位是第62位
        while bit > 0 {
            bit -= 1
            result = result.cyclotomicSquare()
            if (SM9Params.t &>> UInt64(bit)) & 1 == 1 {
                result = result.mul(f)
            }
        }
        return result
    }

    /// 最终幂 f^((q^12 - 1)/N)。
    /// 简单部分 (q^6 - 1)(q^2 + 1)；困难部分 (q^4 - q^2 + 1)/N 用 Scott 等人的 BN 加法链（3次 t 次幂），
    /// 它精确等于该指数（不是倍数），结果与直接求幂相同。
    static func finalExponentiation(_ f: SM9Fp12) -> SM9Fp12 {
        var m = f.conjugate().mul(f.inverse())
        m = m.frobenius(2).mul(m)

        let fa = powT(m)
        let fb = powT(fa)
        let fc = powT(fb)

        let y0 = m.frobenius(1).mul(m.frobenius(2)).mul(m.frobenius(3))
        let y1 = m.conjugate()
        let y2 = fb.frobenius(2)
        let y3 = fa.frobenius(1).conjugate()
        let y4 = fa.mul(fb.frobenius(1)).conjugate()
        let y5 = fb.conjugate()
        let y6 = fc.mul(fc.frobenius(1)).conjugate()

        var t0 = y6.cyclotomicSquare().mul(y4).mul(y5)
        var t1 = y3.mul(y5).mul(t0)
        t0 = t0.mul(y2)
        t1 = t1.cyclotomicSquare().mul(t0).cyclotomicSquare()
        t0 = t1.mul(y1)
        t1 = t1.mul(y0)
        return t0.cyclotomicSquare().mul(t1)
    }

    /// e(P, Q)。nil 表示无穷远点，此时结果为 1。
    static func pairing(_ p: SM9Affine<SM9Fp>?, _ q: SM9Affine<SM9Fp2>?) -> SM9Fp12 {
        guard let p = p, let q = q else {
            return SM9Fp12.one
        }
        return finalExponentiation(millerLoop(p, q))
    }

    // MARK: - GT 中的秘密指数幂

    private static let windowWidth = 5
    private static let windowCount = 52
    private static let tableEntries = 16
    /// 一个 Fq12 元素占 48 个 UInt64
    private static let elementWords = 48

    /// g^k，g 必须在 GT（分圆子群）里，k < 2^256 是秘密。
    /// 5位 Booth 固定窗口：表项 g^1...g^16，每个窗口扫描整张表，负数窗口用共轭（分圆子群里的逆）掩码选择，
    /// 窗口值 0 时掩码选择 1。循环次数和内存访问都与 k 无关。
    static func powSecret(_ g: SM9Fp12, _ scalar: BigInt256) -> SM9Fp12 {
        let entries = tableEntries
        let words = elementWords
        return withUnsafeTemporaryAllocation(of: SM9Fp12.self, capacity: entries) { table -> SM9Fp12 in
            guard let base = table.baseAddress else {
                return SM9Fp12.one
            }
            base.initialize(to: g)
            for index in 1..<entries {
                let multiple = index + 1
                let value =
                    multiple % 2 == 0 ? table[multiple / 2 - 1].cyclotomicSquare() : table[index - 1].mul(g)
                (base + index).initialize(to: value)
            }
            defer {
                secureWipe(UnsafeMutableRawBufferPointer(table))
            }
            var result = SM9Fp12.one
            withUnsafeTemporaryAllocation(of: UInt64.self, capacity: entries + words) { scratch in
                guard let masks = scratch.baseAddress else {
                    return
                }
                let selectedWords = masks + entries
                let raw = UnsafeRawPointer(base).assumingMemoryBound(to: UInt64.self)
                for window in stride(from: windowCount - 1, through: 0, by: -1) {
                    if window != windowCount - 1 {
                        for _ in 0..<windowWidth {
                            result = result.cyclotomicSquare()
                        }
                    }
                    let (digit, negate) = sm9BoothRecode(
                        sm9BoothWindow(scalar, index: window, width: windowWidth), width: UInt64(windowWidth))
                    fillSelectionMasks(digit: digit, masks: masks, count: UInt64(truncatingIfNeeded: entries))
                    sm9ScanTable(
                        table: raw, masks: UnsafePointer(masks), count: entries, words: words, output: selectedWords)
                    var selected = UnsafeRawPointer(selectedWords).load(as: SM9Fp12.self)
                    selected = SM9Fp12.select(opaqueMask(negate), selected.conjugate(), selected)
                    selected = SM9Fp12.select(opaqueMask(zeroMask(digit)), SM9Fp12.one, selected)
                    result = result.mul(selected)
                }
                secureWipe(UnsafeMutableRawBufferPointer(scratch))
            }
            return result
        }
    }
}

// MARK: - 主公钥的固定配对值缓存

/// g = e(P1, Ppub-s) 和 g = e(Ppub-e, P2) 只取决于公开的主公钥，按主公钥的编码缓存最近用过的几个。
/// 只缓存公开数据；线程安全。
final class SM9MasterPairingCache: @unchecked Sendable {
    static let shared = SM9MasterPairingCache()
    private static let capacity = 8

    private let lock = NSLock()
    private var entries: [(key: [UInt8], value: SM9Fp12)] = []

    private func lookup(_ key: [UInt8], compute: () -> SM9Fp12) -> SM9Fp12 {
        lock.lock()
        if let index = entries.firstIndex(where: { $0.key == key }) {
            let value = entries[index].value
            lock.unlock()
            return value
        }
        lock.unlock()
        let value = compute()
        lock.lock()
        defer { lock.unlock() }
        if !entries.contains(where: { $0.key == key }) {
            if entries.count >= SM9MasterPairingCache.capacity {
                entries.removeFirst()
            }
            entries.append((key, value))
        }
        return value
    }

    /// e(P1, Ppub-s)
    func signBase(_ ppubS: SM9Affine<SM9Fp2>) -> SM9Fp12 {
        return lookup([0x01] + SM9Points.encodeG2(ppubS)) { SM9Pairing.pairing(SM9Points.p1, ppubS) }
    }

    /// e(Ppub-e, P2)
    func encryptBase(_ ppubE: SM9Affine<SM9Fp>) -> SM9Fp12 {
        return lookup([0x03] + SM9Points.encodeG1(ppubE)) { SM9Pairing.pairing(ppubE, SM9Points.p2) }
    }
}

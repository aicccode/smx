// SM9 的 G1（E: y^2 = x^3 + 5，定义在 Fq 上）与 G2（扭曲线 E': y^2 = x^3 + 5u，定义在 Fq2 上）。
//
// 两条曲线 a = 0，共用一份 Jacobian 坐标实现（对坐标域泛型，整模块优化时会特化）。
// - 秘密标量：multiplySecret，5位 Booth 固定窗口 + 全表掩码扫描，循环次数、内存访问都不依赖标量。
// - 公开标量：multiplyPublic，wNAF，可变时间（验签、公开的 H1 值、子群检查）。

/// G1/G2 坐标域需要的运算
protocol SM9CurveField {
    static var zero: Self { get }
    static var one: Self { get }
    /// 曲线方程的常数项 b
    static var curveB: Self { get }
    /// 一个元素占多少个 UInt64（查表扫描用）
    static var words: Int { get }
    var isZeroMask: UInt64 { get }
    var isZero: Bool { get }
    static func == (lhs: Self, rhs: Self) -> Bool
    static func select(_ mask: UInt64, _ a: Self, _ b: Self) -> Self
    func add(_ o: Self) -> Self
    func sub(_ o: Self) -> Self
    func double() -> Self
    func neg() -> Self
    func mul(_ o: Self) -> Self
    func square() -> Self
    func inverse() -> Self
}

extension SM9Fp: SM9CurveField {
    static var curveB: SM9Fp { return SM9Fp(small: 5) }
    static var words: Int { return 4 }
}

extension SM9Fp2: SM9CurveField {
    static var curveB: SM9Fp2 { return SM9Fp2(.zero, SM9Fp(small: 5)) }
    static var words: Int { return 8 }
}

/// 仿射点。无穷远点不用仿射表示（编码里也不存在）。
struct SM9Affine<F: SM9CurveField> {
    var x: F
    var y: F

    var isOnCurve: Bool {
        return y.square() == x.square().mul(x).add(F.curveB)
    }

    var jacobian: SM9Jacobian<F> { return SM9Jacobian(x: x, y: y, z: .one) }

    func negated() -> SM9Affine { return SM9Affine(x: x, y: y.neg()) }
}

typealias SM9G1 = SM9Jacobian<SM9Fp>
typealias SM9G2 = SM9Jacobian<SM9Fp2>

struct SM9Jacobian<F: SM9CurveField> {
    var x: F
    var y: F
    var z: F

    static var infinity: SM9Jacobian { return SM9Jacobian(x: .one, y: .one, z: .zero) }

    @inline(__always)
    var isInfinity: Bool { return z.isZero }

    @inline(__always)
    static func select(_ mask: UInt64, _ a: SM9Jacobian, _ b: SM9Jacobian) -> SM9Jacobian {
        return SM9Jacobian(x: F.select(mask, a.x, b.x), y: F.select(mask, a.y, b.y), z: F.select(mask, a.z, b.z))
    }

    func negated() -> SM9Jacobian { return SM9Jacobian(x: x, y: y.neg(), z: z) }

    /// 倍点 dbl-2009-l（a = 0），2M + 5S。无分支：无穷远点得到 Z3 = 0（素数阶群里没有 y = 0 的点）。
    @inline(__always)
    func doubled() -> SM9Jacobian {
        let a = x.square()
        let b = y.square()
        let c = b.square()
        let d = x.add(b).square().sub(a).sub(c).double()
        let e = a.double().add(a)
        let f = e.square()
        let x3 = f.sub(d.double())
        let y3 = e.mul(d.sub(x3)).sub(c.double().double().double())
        let z3 = y.mul(z).double()
        return SM9Jacobian(x: x3, y: y3, z: z3)
    }

    /// add-2007-bl 的公式部分，不处理任何特殊情况。返回 (结果, H, r)，H = r = 0 表示两点相等。
    @inline(__always)
    private func addFormula(_ o: SM9Jacobian) -> (SM9Jacobian, F, F) {
        let z1z1 = z.square()
        let z2z2 = o.z.square()
        let u1 = x.mul(z2z2)
        let u2 = o.x.mul(z1z1)
        let s1 = y.mul(o.z).mul(z2z2)
        let s2 = o.y.mul(z).mul(z1z1)
        let h = u2.sub(u1)
        let r = s2.sub(s1)
        let hh = h.square()
        let hhh = h.mul(hh)
        let v = u1.mul(hh)
        let x3 = r.square().sub(hhh).sub(v.double())
        let y3 = r.mul(v.sub(x3)).sub(s1.mul(hhh))
        let z3 = z.mul(o.z).mul(h)
        return (SM9Jacobian(x: x3, y: y3, z: z3), h, r)
    }

    /// 恒定时间完整加法：无穷远输入、P = -Q（公式自然得到 Z3 = 0）都用掩码处理；
    /// P = Q 只在 handleDoubling（公开值）为 true 时处理。
    @inline(__always)
    func addMasked(_ o: SM9Jacobian, handleDoubling: Bool) -> SM9Jacobian {
        var (result, h, r) = addFormula(o)
        if handleDoubling {
            result = SM9Jacobian.select(opaqueMask(h.isZeroMask & r.isZeroMask), doubled(), result)
        }
        result = SM9Jacobian.select(opaqueMask(z.isZeroMask), o, result)
        return SM9Jacobian.select(opaqueMask(o.z.isZeroMask), self, result)
    }

    /// 完整加法，可变时间，只用于公开数据
    func addPublic(_ o: SM9Jacobian) -> SM9Jacobian {
        if isInfinity { return o }
        if o.isInfinity { return self }
        let (result, h, r) = addFormula(o)
        if h.isZero {
            return r.isZero ? doubled() : SM9Jacobian.infinity
        }
        return result
    }

    /// 转仿射坐标，恒定时间求逆。无穷远点返回 nil（是否无穷远不是秘密：所有调用方都会公开这个结论）。
    func toAffine() -> SM9Affine<F>? {
        if isInfinity { return nil }
        let zInverse = z.inverse()
        let zInverse2 = zInverse.square()
        return SM9Affine(x: x.mul(zInverse2), y: y.mul(zInverse2).mul(zInverse))
    }

    /// 是否表示同一个点（可变时间，只用于公开数据）
    func equalsPublic(_ o: SM9Jacobian) -> Bool {
        if isInfinity || o.isInfinity { return isInfinity && o.isInfinity }
        let z1z1 = z.square()
        let z2z2 = o.z.square()
        return x.mul(z2z2) == o.x.mul(z1z1) && y.mul(o.z).mul(z2z2) == o.y.mul(z).mul(z1z1)
    }

    // MARK: - 秘密标量乘法

    private static var windowWidth: Int { return 5 }
    private static var windowCount: Int { return 52 }
    private static var tableEntries: Int { return 16 }

    /// [k]P，k < 2^256 是秘密，P 必须是阶为 N 的点（可以是秘密点，例如用户私钥）。
    ///
    /// 同 SM2 的论证：累加值与窗口点相等只可能出现在最后一个窗口，所以只有那里处理倍点。
    /// 表项 [i]P（i = 1...16）由无分支的公式算出：偶数项倍点，奇数项 [2j]P + P，对素数阶的点都不是特殊情况。
    static func multiplySecret(_ point: SM9Jacobian, _ scalar: BigInt256) -> SM9Jacobian {
        let words = 3 * F.words
        let entries = tableEntries
        return withUnsafeTemporaryAllocation(of: SM9Jacobian.self, capacity: entries) { table -> SM9Jacobian in
            guard let base = table.baseAddress else {
                return infinity
            }
            base.initialize(to: point)
            for index in 1..<entries {
                let multiple = index + 1
                let value =
                    multiple % 2 == 0
                    ? table[multiple / 2 - 1].doubled()
                    : table[index - 1].addFormula(point).0
                (base + index).initialize(to: value)
            }
            defer {
                secureWipe(UnsafeMutableRawBufferPointer(table))
            }

            var result = infinity
            withUnsafeTemporaryAllocation(of: UInt64.self, capacity: entries + words) { scratch in
                guard let masks = scratch.baseAddress else {
                    return
                }
                let selectedWords = masks + entries
                let raw = UnsafeRawPointer(base).assumingMemoryBound(to: UInt64.self)
                for window in stride(from: windowCount - 1, through: 0, by: -1) {
                    if window != windowCount - 1 {
                        for _ in 0..<windowWidth {
                            result = result.doubled()
                        }
                    }
                    let (digit, negate) = sm9BoothRecode(
                        sm9BoothWindow(scalar, index: window, width: windowWidth), width: UInt64(windowWidth))
                    fillSelectionMasks(digit: digit, masks: masks, count: UInt64(truncatingIfNeeded: entries))
                    sm9ScanTable(
                        table: raw, masks: UnsafePointer(masks), count: entries, words: words, output: selectedWords)
                    // digit = 0 时全 0：Z = 0 即无穷远，由 addMasked 的掩码处理
                    var selected = UnsafeRawPointer(selectedWords).load(as: SM9Jacobian.self)
                    selected.y = F.select(opaqueMask(negate), selected.y.neg(), selected.y)
                    result = result.addMasked(selected, handleDoubling: window == 0)
                }
                secureWipe(UnsafeMutableRawBufferPointer(scratch))
            }
            return result
        }
    }

    // MARK: - 公开标量乘法

    /// [k]P，k 和 P 都是公开的。宽度5的 wNAF，可变时间。
    static func multiplyPublic(_ point: SM9Jacobian, _ scalar: BigInt256) -> SM9Jacobian {
        var odd = [point]
        let doubledPoint = point.doubled()
        for index in 1..<8 {
            odd.append(odd[index - 1].addPublic(doubledPoint))
        }
        var digits = [Int8]()
        digits.reserveCapacity(258)
        var remaining = scalar
        var carryBit: UInt64 = 0  // 处理加上负窗口值时超出256位的进位
        while !remaining.isZero || carryBit != 0 {
            var digit: Int64 = 0
            if remaining.l0 & 1 == 1 {
                digit = Int64(truncatingIfNeeded: remaining.l0 & 31)
                if digit >= 16 {
                    digit -= 32
                }
                if digit > 0 {
                    remaining = remaining.sub(BigInt256(UInt64(digit), 0, 0, 0)).0
                } else {
                    let (sum, carry) = remaining.addingWithCarry(BigInt256(UInt64(-digit), 0, 0, 0))
                    remaining = sum
                    carryBit |= carry
                }
            }
            digits.append(Int8(truncatingIfNeeded: digit))
            remaining = remaining.shiftRight1()
            remaining.l3 |= carryBit << 63
            carryBit = 0
        }
        var result = infinity
        for digit in digits.reversed() {
            result = result.doubled()
            if digit > 0 {
                result = result.addPublic(odd[Int(digit) >> 1])
            } else if digit < 0 {
                result = result.addPublic(odd[Int(-digit) >> 1].negated())
            }
        }
        return result
    }
}

// MARK: - Booth 重编码与全表扫描

/// Booth 重编码：输入 width+1 位窗口，输出 0...2^(width-1) 的数字和取负掩码
@inline(__always)
func sm9BoothRecode(_ window: UInt64, width: UInt64) -> (digit: UInt64, negate: UInt64) {
    let negate = 0 &- ((window &>> width) & 1)
    let flipped = (UInt64(1) &<< (width &+ 1)) &- window &- 1
    let value = (flipped & negate) | (window & ~negate)
    return ((value &>> 1) &+ (value & 1), negate)
}

/// 第 index 个窗口（位 index*width-1 到 index*width+width-1），index 是公开值
@inline(__always)
func sm9BoothWindow(_ scalar: BigInt256, index: Int, width: Int) -> UInt64 {
    let mask = (UInt64(1) &<< UInt64(truncatingIfNeeded: width &+ 1)) &- 1
    if index == 0 {
        return (scalar.l0 &<< 1) & mask
    }
    return scalar.bits(from: index &* width &- 1) & mask
}

/// 把每个表项（words 个 UInt64）与掩码相与后累积到 output。每一项的每个字都会被读取；
/// 循环只由公开的 count、words 控制。不内联：掩码从内存传入，优化器看不到它们只有一个非 0。
@inline(never)
func sm9ScanTable(
    table: UnsafePointer<UInt64>, masks: UnsafePointer<UInt64>, count: Int, words: Int,
    output: UnsafeMutablePointer<UInt64>
) {
    output.initialize(repeating: 0, count: words)
    var index = 0
    while index < count {
        let mask = masks[index]
        let entry = table + index &* words
        var word = 0
        while word < words {
            output[word] |= entry[word] & mask
            word &+= 1
        }
        index &+= 1
    }
}

// MARK: - G1/G2 常量与编码

enum SM9Points {
    /// G1 生成元 P1
    static var p1: SM9Affine<SM9Fp> {
        return SM9Affine(
            x: SM9Fp(
                canonical: BigInt256(
                    0xE8C4_E481_7C66_DDDD, 0xE1E4_0869_09DC_3280, 0xF5ED_0704_487D_01D6, 0x93DE_051D_62BF_718F)),
            y: SM9Fp(
                canonical: BigInt256(
                    0x0C46_4CD7_0A3E_A616, 0x1C1C_00CB_FA60_2435, 0x6310_6512_5C39_5BBC, 0x21FE_8DDA_4F21_E607)))
    }

    /// G2 生成元 P2（x = x0 + x1 u）
    static var p2: SM9Affine<SM9Fp2> {
        return SM9Affine(
            x: SM9Fp2(
                SM9Fp(
                    canonical: BigInt256(
                        0xF9B7_213B_AF82_D65B, 0xEE26_5948_D19C_17AB, 0xD2AA_B97F_D34E_C120, 0x3722_7552_9213_0B08)),
                SM9Fp(
                    canonical: BigInt256(
                        0x5480_6C11_D880_6141, 0xF1DD_2C19_0F5E_93C4, 0x597B_6027_B441_A01F, 0x85AE_F3D0_7864_0C98))),
            y: SM9Fp2(
                SM9Fp(
                    canonical: BigInt256(
                        0x6215_BBA5_C999_A7C7, 0x47EF_BA98_A71A_0811, 0x5F31_7015_3D27_8FF2, 0xA7CF_28D5_19BE_3DA6)),
                SM9Fp(
                    canonical: BigInt256(
                        0x856D_C76B_84EB_EB96, 0x0736_A96F_A347_C8BD, 0x66BA_0D26_2CBE_E6ED, 0x1750_9B09_2E84_5C12))))
    }

    /// 扭曲线上的 Frobenius：pi(x, y) = (conj(x) * u^(-(q-1)/3), conj(y) * u^(-(q-1)/2))，两个常量都在 Fq 内
    static func frobenius(_ point: SM9Affine<SM9Fp2>) -> SM9Affine<SM9Fp2> {
        let piX = SM9Fp(
            montgomery: BigInt256(
                0x646A_4B5A_4E67_83B9, 0xD5E4_017F_8D98_0F9D, 0x8D8B_F6FD_0CDF_E790, 0x2D4A_C18B_775A_8F7B))
        let piY = SM9Fp(
            montgomery: BigInt256(
                0xABBA_AC18_A46A_2054, 0x46EE_5756_1222_C759, 0x1DAE_609F_A0E2_3561, 0x1DF7_113D_AE0A_DC3C))
        return SM9Affine(x: point.x.conjugate().mulFp(piX), y: point.y.conjugate().mulFp(piY))
    }

    /// G2 子群检查：对 BN 曲线，扭曲线上的点 Q 属于 G2 当且仅当 pi(Q) = [6t^2]Q（6t^2 = q - N ≡ q mod N）。
    /// 公开数据，可变时间；测试里与 [N]Q == O 对照。
    static func isInG2(_ point: SM9Affine<SM9Fp2>) -> Bool {
        let lhs = frobenius(point).jacobian
        let rhs = SM9G2.multiplyPublic(point.jacobian, SM9Params.sixTSquared)
        return lhs.equalsPublic(rhs)
    }

    // MARK: 编码

    /// 04 || x || y
    static func encodeG1(_ point: SM9Affine<SM9Fp>) -> [UInt8] {
        var out = [UInt8](repeating: 0x04, count: 65)
        out.withUnsafeMutableBufferPointer { buffer in
            guard let base = buffer.baseAddress else { return }
            point.x.writeBE(to: base + 1)
            point.y.writeBE(to: base + 33)
        }
        return out
    }

    /// x || y（哈希和 KDF 里使用）
    static func xyG1(_ point: SM9Affine<SM9Fp>) -> [UInt8] {
        return Array(encodeG1(point)[1...])
    }

    /// 04 || x1 || x0 || y1 || y0
    static func encodeG2(_ point: SM9Affine<SM9Fp2>) -> [UInt8] {
        var out = [UInt8](repeating: 0x04, count: 129)
        out.withUnsafeMutableBufferPointer { buffer in
            guard let base = buffer.baseAddress else { return }
            point.x.c1.writeBE(to: base + 1)
            point.x.c0.writeBE(to: base + 33)
            point.y.c1.writeBE(to: base + 65)
            point.y.c0.writeBE(to: base + 97)
        }
        return out
    }

    /// 读取32字节大端坐标，要求小于 q
    private static func coordinate(_ bytes: UnsafePointer<UInt8>) -> SM9Fp? {
        let value = BigInt256.fromBEPointer(bytes)
        guard value < SM9Params.q else {
            return nil
        }
        return SM9Fp(canonical: value)
    }

    /// 65字节 04 || x || y，坐标小于 q 且在曲线上（G1 的余因子为 1，在曲线上即在群里；仿射编码不含无穷远点）
    static func decodeG1(_ bytes: [UInt8]) -> SM9Affine<SM9Fp>? {
        guard bytes.count == 65, bytes[0] == 0x04 else {
            return nil
        }
        return bytes.withUnsafeBufferPointer { buffer -> SM9Affine<SM9Fp>? in
            guard let base = buffer.baseAddress, let x = coordinate(base + 1), let y = coordinate(base + 33) else {
                return nil
            }
            let point = SM9Affine(x: x, y: y)
            return point.isOnCurve ? point : nil
        }
    }

    /// 129字节 04 || x1 || x0 || y1 || y0，坐标小于 q，在扭曲线上，并且在 G2 子群里
    static func decodeG2(_ bytes: [UInt8]) -> SM9Affine<SM9Fp2>? {
        guard bytes.count == 129, bytes[0] == 0x04 else {
            return nil
        }
        return bytes.withUnsafeBufferPointer { buffer -> SM9Affine<SM9Fp2>? in
            guard let base = buffer.baseAddress, let x1 = coordinate(base + 1), let x0 = coordinate(base + 33),
                let y1 = coordinate(base + 65), let y0 = coordinate(base + 97)
            else {
                return nil
            }
            let point = SM9Affine(x: SM9Fp2(x0, x1), y: SM9Fp2(y0, y1))
            return point.isOnCurve && isInG2(point) ? point : nil
        }
    }

    /// 十六进制（大小写均可，长度必须精确）解码 G1 点
    static func decodeG1Hex(_ hex: String) -> SM9Affine<SM9Fp>? {
        guard hex.utf8.count == 130, let bytes = Hex.decodeStrict(hex) else {
            return nil
        }
        return decodeG1(bytes)
    }

    static func decodeG2Hex(_ hex: String) -> SM9Affine<SM9Fp2>? {
        guard hex.utf8.count == 258, let bytes = Hex.decodeStrict(hex) else {
            return nil
        }
        return decodeG2(bytes)
    }
}

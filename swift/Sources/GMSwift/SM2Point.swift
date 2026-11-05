// Jacobian 坐标点运算与标量乘法。
//
// 标量乘法分两类：
// - 秘密标量（keygen、签名随机数、解密、密钥交换）：multiplyConstantTime / multiplyGenerator，
//   固定窗口 + 全表扫描 + 掩码处理异常情况，循环次数和内存访问都不依赖标量。
// - 公开标量（只有验签和密钥交换里公开的 x'）：multiplyPublicPair，wNAF + Strauss-Shamir，可变时间。

/// Booth 重编码：输入 width+1 位窗口（含下一窗口的借位），输出 0...2^(width-1) 的数字和取负掩码。
@inline(__always)
private func boothRecode(_ window: UInt64, width: UInt64) -> (digit: UInt64, negate: UInt64) {
    let negate = 0 &- ((window &>> width) & 1)
    let flipped = (UInt64(1) &<< (width &+ 1)) &- window &- 1
    let value = (flipped & negate) | (window & ~negate)
    return ((value &>> 1) &+ (value & 1), negate)
}

/// 取第 index 个窗口（位 index*width-1 到 index*width+width-1）。index 是公开值。
@inline(__always)
private func boothWindow(_ scalar: BigInt256, index: Int, width: Int) -> UInt64 {
    let mask = (UInt64(1) &<< UInt64(truncatingIfNeeded: width &+ 1)) &- 1
    if index == 0 {
        return (scalar.l0 &<< 1) & mask
    }
    return scalar.bits(from: index &* width &- 1) & mask
}

/// y 取负（mask 全 1 时），保持 0 的规范表示
@inline(__always)
private func conditionalNegate(_ y: FpElement, _ mask: UInt64) -> FpElement {
    return FpElement.select(mask, y.negate(), y)
}

struct JacobianPoint {
    var x: FpElement
    var y: FpElement
    var z: FpElement

    static let infinity = JacobianPoint(x: .one, y: .one, z: .zero)

    @inline(__always)
    var isInfinity: Bool { return z.isZero }

    @inline(__always)
    static func select(_ mask: UInt64, _ a: JacobianPoint, _ b: JacobianPoint) -> JacobianPoint {
        return JacobianPoint(
            x: FpElement.select(mask, a.x, b.x),
            y: FpElement.select(mask, a.y, b.y),
            z: FpElement.select(mask, a.z, b.z)
        )
    }

    // MARK: - 点运算

    /// 倍点（dbl-2001-b，a = -3，3M + 5S）。无分支：无穷远点和 y = 0 的点都自然得到 Z3 = 0。
    @inline(__always)
    func twice() -> JacobianPoint {
        let delta = z.square()
        let gamma = y.square()
        let beta = x.multiply(gamma)
        let alpha = x.subtract(delta).multiply(x.add(delta)).triple()
        let beta4 = beta.double().double()
        let x3 = alpha.square().subtract(beta4.double())
        let z3 = y.add(z).square().subtract(gamma).subtract(delta)
        let gammaSquared = gamma.square().double()
        let y3 = alpha.multiply(beta4.subtract(x3)).subtract(gammaSquared.double().double())
        return JacobianPoint(x: x3, y: y3, z: z3)
    }

    /// 混合加法（Q 是仿射坐标），可变时间，只用于公开数据。Cost: 8M + 3S
    func addAffine(_ qx: FpElement, _ qy: FpElement) -> JacobianPoint {
        if isInfinity {
            return JacobianPoint(x: qx, y: qy, z: .one)
        }

        let z1Squared = z.square()
        let h = qx.multiply(z1Squared).subtract(x)
        let r = qy.multiply(z1Squared).multiply(z).subtract(y)

        if h.isZero {
            return r.isZero ? twice() : JacobianPoint.infinity
        }

        let hSquared = h.square()
        let hCubed = h.multiply(hSquared)
        let u1h2 = x.multiply(hSquared)

        let x3 = r.square().subtract(hCubed).subtract(u1h2.double())
        let y3 = r.multiply(u1h2.subtract(x3)).subtract(y.multiply(hCubed))
        return JacobianPoint(x: x3, y: y3, z: z.multiply(h))
    }

    /// 完整点加法，可变时间，只用于公开数据。Cost: 12M + 4S
    func addJacobian(_ other: JacobianPoint) -> JacobianPoint {
        if isInfinity { return other }
        if other.isInfinity { return self }

        let z1Squared = z.square()
        let z2Squared = other.z.square()
        let u1 = x.multiply(z2Squared)
        let s1 = y.multiply(z2Squared).multiply(other.z)
        let h = other.x.multiply(z1Squared).subtract(u1)
        let r = other.y.multiply(z1Squared).multiply(z).subtract(s1)

        if h.isZero {
            return r.isZero ? twice() : JacobianPoint.infinity
        }

        let hSquared = h.square()
        let hCubed = h.multiply(hSquared)
        let u1h2 = u1.multiply(hSquared)

        let x3 = r.square().subtract(hCubed).subtract(u1h2.double())
        let y3 = r.multiply(u1h2.subtract(x3)).subtract(s1.multiply(hCubed))
        return JacobianPoint(x: x3, y: y3, z: z.multiply(other.z).multiply(h))
    }

    /// 恒定时间混合加法。Q = (qx, qy, qIsInfinity 掩码)。
    /// 无穷远输入用掩码处理；P = -Q 时公式自然得到 Z3 = 0；
    /// P = Q 只有 handleDoubling（公开值）为 true 时才处理，见调用方的说明。
    @inline(__always)
    private func addAffineMasked(
        _ qx: FpElement, _ qy: FpElement, qIsInfinity: UInt64, handleDoubling: Bool
    ) -> JacobianPoint {
        let z1Squared = z.square()
        let h = qx.multiply(z1Squared).subtract(x)
        let r = qy.multiply(z1Squared).multiply(z).subtract(y)
        let hSquared = h.square()
        let hCubed = h.multiply(hSquared)
        let u1h2 = x.multiply(hSquared)
        let x3 = r.square().subtract(hCubed).subtract(u1h2.double())
        let y3 = r.multiply(u1h2.subtract(x3)).subtract(y.multiply(hCubed))
        var result = JacobianPoint(x: x3, y: y3, z: z.multiply(h))

        if handleDoubling {
            result = JacobianPoint.select(h.value.isZeroMask & r.value.isZeroMask, twice(), result)
        }
        let affine = JacobianPoint(x: qx, y: qy, z: .one)
        result = JacobianPoint.select(z.value.isZeroMask, affine, result)
        return JacobianPoint.select(qIsInfinity, self, result)
    }

    /// 恒定时间完整加法，异常情况的处理同 addAffineMasked。Q 的无穷远由 Z = 0 表示。
    @inline(__always)
    private func addMasked(_ other: JacobianPoint, handleDoubling: Bool) -> JacobianPoint {
        let z1Squared = z.square()
        let z2Squared = other.z.square()
        let u1 = x.multiply(z2Squared)
        let s1 = y.multiply(z2Squared).multiply(other.z)
        let h = other.x.multiply(z1Squared).subtract(u1)
        let r = other.y.multiply(z1Squared).multiply(z).subtract(s1)
        let hSquared = h.square()
        let hCubed = h.multiply(hSquared)
        let u1h2 = u1.multiply(hSquared)
        let x3 = r.square().subtract(hCubed).subtract(u1h2.double())
        let y3 = r.multiply(u1h2.subtract(x3)).subtract(s1.multiply(hCubed))
        var result = JacobianPoint(x: x3, y: y3, z: z.multiply(other.z).multiply(h))

        if handleDoubling {
            result = JacobianPoint.select(h.value.isZeroMask & r.value.isZeroMask, twice(), result)
        }
        result = JacobianPoint.select(z.value.isZeroMask, other, result)
        return JacobianPoint.select(other.z.value.isZeroMask, self, result)
    }

    /// 转换到仿射坐标（需要一次模逆，恒定时间）
    func toAffine() -> (FpElement, FpElement)? {
        if isInfinity { return nil }
        let zInverse = z.invertedUnchecked()
        let zInverseSquared = zInverse.square()
        return (x.multiply(zInverseSquared), y.multiply(zInverseSquared).multiply(zInverse))
    }

    /// 判断 X/Z^2 是否等于 candidate（无需求逆）。candidate 必须在 [0, p) 内，自身不能是无穷远点。
    func affineXEquals(_ candidate: BigInt256) -> Bool {
        return FpElement(unchecked: candidate).multiply(z.square()) == x
    }

    // MARK: - 恒定时间可变基点标量乘法

    private static let variableBaseWidth = 5
    private static let variableBaseWindows = 52
    private static let variableBaseEntries = 16

    private typealias VariableBaseTable = (
        JacobianPoint, JacobianPoint, JacobianPoint, JacobianPoint,
        JacobianPoint, JacobianPoint, JacobianPoint, JacobianPoint,
        JacobianPoint, JacobianPoint, JacobianPoint, JacobianPoint,
        JacobianPoint, JacobianPoint, JacobianPoint, JacobianPoint
    )

    /// [k]P，k 可以是任意256位值（包括 0 和 >= n）。P 是公开点，k 是秘密。
    ///
    /// 固定5位 Booth 窗口。累加值 Q = [32m]P 与窗口点 [±d]P 相等只可能发生在最后一个窗口：
    /// 之前的窗口 |32m| 远小于 n，又因 |d| <= 16 < 32，所以只有 m = d = 0（两者都是无穷远，已由掩码处理）。
    /// 因此对曲线上的点（阶为素数 n）只需在最后一个窗口付出多算一次倍点的代价。
    /// 不在曲线上的点（getSb/getSa 不校验 pA/pB，这是既有行为）阶可能很小，
    /// isOnCurve 为 false 时每个窗口都处理；该判断只依赖公开的点。
    static func multiplyConstantTime(
        x px: FpElement, y py: FpElement, scalar: BigInt256, isOnCurve: Bool
    ) -> JacobianPoint {
        let base = JacobianPoint(x: px, y: py, z: .one)
        var storage: VariableBaseTable = (
            base, base, base, base, base, base, base, base, base, base, base, base, base, base, base, base
        )
        return withUnsafeMutableBytes(of: &storage) { raw -> JacobianPoint in
            let table = raw.bindMemory(to: JacobianPoint.self)
            // 表项 table[i] = [i+1]P。P 是公开的，这里可以用可变时间运算。
            for index in 1..<variableBaseEntries {
                let multiple = index + 1
                table[index] =
                    multiple % 2 == 0
                    ? table[multiple / 2 - 1].twice()
                    : table[index - 1].addJacobian(base)
            }

            var result = JacobianPoint.infinity
            for window in stride(from: variableBaseWindows - 1, through: 0, by: -1) {
                if window != variableBaseWindows - 1 {
                    for _ in 0..<variableBaseWidth {
                        result = result.twice()
                    }
                }
                let (digit, negate) = boothRecode(
                    boothWindow(scalar, index: window, width: variableBaseWidth),
                    width: UInt64(truncatingIfNeeded: variableBaseWidth)
                )
                // 扫描整张表；digit = 0 时全部掩码为 0，得到 Z = 0 即无穷远
                var selected = JacobianPoint(x: .zero, y: .zero, z: .zero)
                for index in 0..<variableBaseEntries {
                    let mask = zeroMask(digit ^ UInt64(truncatingIfNeeded: index &+ 1))
                    let entry = table[index]
                    selected.x.value.l0 |= entry.x.value.l0 & mask
                    selected.x.value.l1 |= entry.x.value.l1 & mask
                    selected.x.value.l2 |= entry.x.value.l2 & mask
                    selected.x.value.l3 |= entry.x.value.l3 & mask
                    selected.y.value.l0 |= entry.y.value.l0 & mask
                    selected.y.value.l1 |= entry.y.value.l1 & mask
                    selected.y.value.l2 |= entry.y.value.l2 & mask
                    selected.y.value.l3 |= entry.y.value.l3 & mask
                    selected.z.value.l0 |= entry.z.value.l0 & mask
                    selected.z.value.l1 |= entry.z.value.l1 & mask
                    selected.z.value.l2 |= entry.z.value.l2 & mask
                    selected.z.value.l3 |= entry.z.value.l3 & mask
                }
                selected.y = conditionalNegate(selected.y, negate)
                result = result.addMasked(selected, handleDoubling: window == 0 || !isOnCurve)
            }
            return result
        }
    }

    // MARK: - 恒定时间固定基点（G）标量乘法

    /// [k]G，k 可以是任意256位值。6位 Booth 窗口，共43个窗口，每个窗口查一张预计算表，不需要倍点。
    ///
    /// 累加值 R 满足 |R| < 0.51 * 2^(6i)，窗口点是 d * 2^(6i)（d != 0），在第 42 个窗口之前都远小于 n，
    /// 不可能相等或互为相反数；所以只有最后一个窗口需要处理倍点情况。
    static func multiplyGenerator(_ scalar: BigInt256) -> JacobianPoint {
        let table = GeneratorTables.comb.pointer
        var result = JacobianPoint.infinity
        for window in 0..<GeneratorTables.combWindows {
            let (digit, negate) = boothRecode(
                boothWindow(scalar, index: window, width: GeneratorTables.combWidth),
                width: UInt64(truncatingIfNeeded: GeneratorTables.combWidth)
            )
            let row = table + window &* GeneratorTables.combEntries &* 8
            var x0: UInt64 = 0
            var x1: UInt64 = 0
            var x2: UInt64 = 0
            var x3: UInt64 = 0
            var y0: UInt64 = 0
            var y1: UInt64 = 0
            var y2: UInt64 = 0
            var y3: UInt64 = 0
            // 扫描整行，访问模式与 digit 无关
            for index in 0..<GeneratorTables.combEntries {
                let mask = zeroMask(digit ^ UInt64(truncatingIfNeeded: index &+ 1))
                let entry = row + index &* 8
                x0 |= entry[0] & mask
                x1 |= entry[1] & mask
                x2 |= entry[2] & mask
                x3 |= entry[3] & mask
                y0 |= entry[4] & mask
                y1 |= entry[5] & mask
                y2 |= entry[6] & mask
                y3 |= entry[7] & mask
            }
            let qy = conditionalNegate(FpElement(unchecked: BigInt256(y0, y1, y2, y3)), negate)
            result = result.addAffineMasked(
                FpElement(unchecked: BigInt256(x0, x1, x2, x3)),
                qy,
                qIsInfinity: zeroMask(digit),
                handleDoubling: window == GeneratorTables.combWindows - 1
            )
        }
        return result
    }

    // MARK: - 可变时间（仅公开标量）

    /// [gScalar]G + [pointScalar]P，两个标量都必须是公开的，且都小于 n。P 可以是无穷远点。
    static func multiplyPublicPair(
        generatorScalar: BigInt256, pointScalar: BigInt256, point: JacobianPoint
    ) -> JacobianPoint {
        let generatorOdd = GeneratorTables.oddMultiples.pointer
        var oddMultiples:
            (
                JacobianPoint, JacobianPoint, JacobianPoint, JacobianPoint,
                JacobianPoint, JacobianPoint, JacobianPoint, JacobianPoint
            ) = (point, point, point, point, point, point, point, point)

        return withUnsafeTemporaryAllocation(of: Int8.self, capacity: 2 * wnafCapacity) { digits -> JacobianPoint in
            let generatorDigits = UnsafeMutableBufferPointer(rebasing: digits[0..<wnafCapacity])
            let pointDigits = UnsafeMutableBufferPointer(rebasing: digits[wnafCapacity...])
            let generatorLength = wnaf(generatorScalar, width: GeneratorTables.oddMultipleWidth, into: generatorDigits)
            let pointLength = wnaf(pointScalar, width: 5, into: pointDigits)

            return withUnsafeMutableBytes(of: &oddMultiples) { raw -> JacobianPoint in
                let table = raw.bindMemory(to: JacobianPoint.self)
                if pointLength > 0 {
                    let doubled = point.twice()
                    for index in 1..<table.count {
                        table[index] = table[index - 1].addJacobian(doubled)
                    }
                }

                var result = JacobianPoint.infinity
                for position in stride(from: max(generatorLength, pointLength) - 1, through: 0, by: -1) {
                    result = result.twice()
                    if position < generatorLength {
                        let digit = Int(generatorDigits[position])
                        if digit != 0 {
                            let entry = generatorOdd + (abs(digit) >> 1) &* 8
                            let qx = BigInt256(entry[0], entry[1], entry[2], entry[3])
                            let qy = FpElement(unchecked: BigInt256(entry[4], entry[5], entry[6], entry[7]))
                            result = result.addAffine(FpElement(unchecked: qx), digit < 0 ? qy.negate() : qy)
                        }
                    }
                    if position < pointLength {
                        let digit = Int(pointDigits[position])
                        if digit != 0 {
                            var entry = table[abs(digit) >> 1]
                            if digit < 0 {
                                entry.y = entry.y.negate()
                            }
                            result = result.addJacobian(entry)
                        }
                    }
                }
                return result
            }
        }
    }

    /// 标量的 wNAF 最多比标量多1位
    private static let wnafCapacity = 258

    /// 计算 width 位 wNAF，返回长度。可变时间，只用于公开标量；scalar 必须小于 n，所以加上窗口值不会溢出。
    private static func wnaf(
        _ scalar: BigInt256, width: Int, into digits: UnsafeMutableBufferPointer<Int8>
    ) -> Int {
        let modulus = Int64(1) << Int64(width)
        var remaining = scalar
        var length = 0
        while !remaining.isZero {
            var digit: Int64 = 0
            if remaining.l0 & 1 == 1 {
                digit = Int64(truncatingIfNeeded: remaining.l0) & (modulus - 1)
                if digit >= modulus / 2 {
                    digit -= modulus
                }
                remaining =
                    digit > 0
                    ? remaining.sub(BigInt256(UInt64(digit), 0, 0, 0)).0
                    : remaining.add(BigInt256(UInt64(-digit), 0, 0, 0)).0
            }
            digits[length] = Int8(truncatingIfNeeded: digit)
            length += 1
            remaining = remaining.shiftRight1()
        }
        return length
    }
}

// MARK: - 基点预计算表（首次使用时生成，只读，线程安全）

struct GeneratorTables: @unchecked Sendable {
    /// 固定基点窗口表：window * entries * 8 个 UInt64，每项是仿射 (x, y)，4 + 4 个 limb
    static let combWidth = 6
    static let combWindows = 43
    static let combEntries = 32
    /// wNAF 奇数倍表：1G, 3G, ..., 127G
    static let oddMultipleWidth = 8
    static let oddMultipleEntries = 64

    let pointer: UnsafePointer<UInt64>

    static let comb: GeneratorTables = {
        var points = [JacobianPoint]()
        points.reserveCapacity(combWindows * combEntries)
        var base = JacobianPoint(x: FpElement(SM2Curve.gx), y: FpElement(SM2Curve.gy), z: .one)
        for _ in 0..<combWindows {
            let start = points.count
            points.append(base)
            for multiple in 2...combEntries {
                points.append(
                    multiple % 2 == 0
                        ? points[start + multiple / 2 - 1].twice()
                        : points[start + multiple - 2].addJacobian(base)
                )
            }
            base = points[start + combEntries - 1].twice()
        }
        return GeneratorTables(pointer: makeAffineTable(points))
    }()

    static let oddMultiples: GeneratorTables = {
        let base = JacobianPoint(x: FpElement(SM2Curve.gx), y: FpElement(SM2Curve.gy), z: .one)
        let doubled = base.twice()
        var points = [base]
        for index in 1..<oddMultipleEntries {
            points.append(points[index - 1].addJacobian(doubled))
        }
        return GeneratorTables(pointer: makeAffineTable(points))
    }()

    /// 批量转仿射（Montgomery 技巧，只做一次求逆）。表在进程生命周期内不释放。
    private static func makeAffineTable(_ points: [JacobianPoint]) -> UnsafePointer<UInt64> {
        var products = [FpElement](repeating: .one, count: points.count)
        var running = FpElement.one
        for (index, point) in points.enumerated() {
            products[index] = running
            running = running.multiply(point.z)
        }
        var inverse = running.invertedUnchecked()

        let table = UnsafeMutablePointer<UInt64>.allocate(capacity: points.count * 8)
        for index in stride(from: points.count - 1, through: 0, by: -1) {
            let point = points[index]
            let zInverse = inverse.multiply(products[index])
            inverse = inverse.multiply(point.z)
            let zInverseSquared = zInverse.square()
            let x = point.x.multiply(zInverseSquared).value
            let y = point.y.multiply(zInverseSquared).multiply(zInverse).value
            let entry = table + index * 8
            entry[0] = x.l0
            entry[1] = x.l1
            entry[2] = x.l2
            entry[3] = x.l3
            entry[4] = y.l0
            entry[5] = y.l1
            entry[6] = y.l2
            entry[7] = y.l3
        }
        return UnsafePointer(table)
    }
}

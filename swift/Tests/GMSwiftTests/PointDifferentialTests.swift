import XCTest

@testable import GMSwift

/// 标量乘法与一个独立的参考实现（仿射坐标 + 逐位 double-and-add，无预计算表）的差分测试。
/// 参考实现只依赖已由 FieldDifferentialTests 校验的域运算。
final class PointDifferentialTests: XCTestCase {
    private struct Affine: Equatable {
        var x: FpElement
        var y: FpElement
    }

    private func referenceAdd(_ p: Affine?, _ q: Affine?) -> Affine? {
        guard let p = p else { return q }
        guard let q = q else { return p }
        let slope: FpElement
        if p.x == q.x {
            if p.y != q.y || p.y.isZero {
                return nil
            }
            let a = FpElement(unchecked: SM2Curve.a)
            slope = p.x.square().triple().add(a).multiply(p.y.double().invert())
        } else {
            slope = q.y.subtract(p.y).multiply(q.x.subtract(p.x).invert())
        }
        let x3 = slope.square().subtract(p.x).subtract(q.x)
        return Affine(x: x3, y: slope.multiply(p.x.subtract(x3)).subtract(p.y))
    }

    private func referenceMultiply(_ point: Affine?, _ k: BigInt256) -> Affine? {
        var result: Affine?
        for bit in stride(from: k.bitLength - 1, through: 0, by: -1) {
            result = referenceAdd(result, result)
            if k.getBit(bit) {
                result = referenceAdd(result, point)
            }
        }
        return result
    }

    private func assertSame(_ point: JacobianPoint, _ expected: Affine?, _ label: String, line: UInt = #line) {
        guard let (x, y) = point.toAffine() else {
            XCTAssertNil(expected, "\(label): got infinity", line: line)
            return
        }
        XCTAssertEqual(expected, Affine(x: x, y: y), label, line: line)
    }

    private let g = Affine(x: FpElement(SM2Curve.gx), y: FpElement(SM2Curve.gy))
    private let n = SM2Curve.n

    private func small(_ value: UInt64) -> BigInt256 {
        return BigInt256(value, 0, 0, 0)
    }

    /// 0, 1, n-1, n, n+1, p, 2^256-1，窗口边界附近的值和随机值
    private func edgeScalars(seed: UInt64, random: Int) -> [BigInt256] {
        var rng = TestRandom(seed: seed)
        var values: [BigInt256] = [
            .zero, .one, n, n.sub(.one).0, n.add(.one).0, SM2Curve.p, BigInt256(.max, .max, .max, .max),
            BigInt256(.max, .max, .max, 0), BigInt256(0, 0, 0, 1 << 63), BigInt256(0, 0, 0, 1 << 59),
        ]
        for value in [2, 3, 15, 16, 17, 31, 32, 33, 34, 62, 63, 64, 65, 66, 127, 128, 129] as [UInt64] {
            values.append(small(value))
            values.append(n.sub(small(value)).0)
            values.append(n.add(small(value)).0)
        }
        values += (0..<random).map { _ in rng.bigInt() }
        return values
    }

    func testMultiplyGeneratorMatchesReference() {
        for k in edgeScalars(seed: 0x1, random: 5) {
            assertSame(JacobianPoint.multiplyGenerator(k), referenceMultiply(g, k), k.toHex())
        }
    }

    /// 固定基点的最后一个窗口：k = n 时低位累加值与窗口点互为相反数，高位附近的值走满最后的窗口
    func testMultiplyGeneratorNearTopWindow() {
        XCTAssertTrue(JacobianPoint.multiplyGenerator(n).isInfinity)
        var scalars: [BigInt256] = [
            BigInt256(.max, .max, .max, .max), BigInt256(0, 0, 0, .max), BigInt256(0, 0, 0, 1 << 63),
        ]
        for shift in 248..<252 {
            scalars.append(BigInt256(0, 0, 0, UInt64(1) << UInt64(shift - 192)))
            scalars.append(BigInt256(.max, .max, .max, (UInt64(1) << UInt64(shift - 192)) - 1))
        }
        for k in scalars {
            assertSame(JacobianPoint.multiplyGenerator(k), referenceMultiply(g, k), k.toHex())
        }
    }

    /// n - 6 的最后一个窗口 Q = [-3]P，窗口点也是 [-3]P：恒定时间路径里唯一需要倍点的情况。
    /// n 的低5位是 3，所以这里还覆盖了最后窗口前后的其它值。
    func testConstantTimeLastWindowDoubling() {
        var rng = TestRandom(seed: 0x6)
        guard let base = referenceMultiply(g, rng.bigInt()) else {
            return XCTFail("base point must be finite")
        }
        let scalars = (1..<40).map { n.sub(small($0)).0 } + (1..<40).map { n.add(small($0)).0 }
        for k in scalars {
            assertSame(
                JacobianPoint.multiplyConstantTime(x: base.x, y: base.y, scalar: k, isOnCurve: true),
                referenceMultiply(base, k), k.toHex())
        }
    }

    func testMultiplyConstantTimeMatchesReference() {
        var rng = TestRandom(seed: 0x2)
        let base = referenceMultiply(g, rng.bigInt())
        for k in edgeScalars(seed: 0x3, random: 5) {
            let expected = referenceMultiply(base, k)
            guard let base = base else {
                return XCTFail("base point must be finite")
            }
            assertSame(
                JacobianPoint.multiplyConstantTime(x: base.x, y: base.y, scalar: k, isOnCurve: true), expected,
                k.toHex())
            // 按“不在曲线上”的完整路径处理同一个点，结果必须相同
            assertSame(
                JacobianPoint.multiplyConstantTime(x: base.x, y: base.y, scalar: k, isOnCurve: false), expected,
                k.toHex())
        }
    }

    /// 不在曲线上的点：getSb/getSa 不校验 pA/pB，所以它们也会走到这里
    func testMultiplyOffCurvePoints() {
        let points = [
            Affine(x: FpElement(.one), y: FpElement(.one)),
            Affine(x: FpElement(BigInt256(0x1234_5678_9, 0, 0, 0)), y: FpElement(BigInt256(0xABCDEF, 0, 0, 0))),
            Affine(x: FpElement(BigInt256(5, 0, 0, 0)), y: FpElement.zero),
        ]
        let scalars = [
            BigInt256.zero, .one, small(2), small(3), small(16), small(33), n, BigInt256(.max, .max, .max, .max),
        ]
        for point in points {
            let ec = ECPoint(x: point.x, y: point.y)
            XCTAssertFalse(ec.isOnCurve())
            for k in scalars {
                let expected = referenceMultiply(point, k)
                let actual = ec.multiply(k)
                if let expected = expected {
                    XCTAssertEqual(actual, ECPoint(x: expected.x, y: expected.y), k.toHex())
                } else {
                    XCTAssertTrue(actual.isInfinity, k.toHex())
                }
            }
        }
    }

    /// y^2 = x^3 - 3x + b' 上阶为 3 的点。阶很小时累加值与窗口点在任何窗口都可能相等，
    /// 这正是 isOnCurve 为 false 时每个窗口都要处理倍点的原因。
    func testMultiplySmallOrderOffCurvePoint() {
        let p = SM2Curve.p
        let squareRootExponent = p.add(.one).0.shiftRight1().shiftRight1()
        let a = FpElement(unchecked: SM2Curve.a)
        var candidate: Affine?
        for value in 2..<200 as Range<UInt64> {
            // 3P = O 当且仅当 3x^4 + 6ax^2 + 12bx - a^2 = 0，由此解出 b
            let x = FpElement(small(value))
            let xSquared = x.square()
            let numerator = a.square().subtract(xSquared.square().triple()).subtract(
                xSquared.multiply(a).double().triple())
            let twelveX = x.double().double().triple()
            let b = numerator.multiply(twelveX.invert())
            let ySquared = xSquared.add(a).multiply(x).add(b)
            let y = FpElement(ySquared.value.modPow(squareRootExponent, p))
            if y.square() == ySquared && !y.isZero {
                candidate = Affine(x: x, y: y)
                break
            }
        }
        guard let point = candidate else {
            return XCTFail("no order-3 point found")
        }
        XCTAssertNil(referenceMultiply(point, small(3)), "point must have order 3")

        let ec = ECPoint(x: point.x, y: point.y)
        XCTAssertFalse(ec.isOnCurve())
        for k in [
            BigInt256.zero, .one, small(2), small(3), small(32), small(33), small(34), small(1000), n,
            BigInt256(.max, .max, .max, .max),
        ] {
            let expected = referenceMultiply(point, k)
            let actual = ec.multiply(k)
            if let expected = expected {
                XCTAssertEqual(actual, ECPoint(x: expected.x, y: expected.y), k.toHex())
            } else {
                XCTAssertTrue(actual.isInfinity, k.toHex())
            }
        }
    }

    func testMultiplyPublicPairMatchesReference() {
        var rng = TestRandom(seed: 0x4)
        let base = referenceMultiply(g, rng.bigInt())
        guard let finiteBase = base else {
            return XCTFail("base point must be finite")
        }
        let jacobian = JacobianPoint(x: finiteBase.x, y: finiteBase.y, z: .one)
        var scalars: [BigInt256] = [
            .zero, .one, small(2), small(3), small(127), small(128), small(129), n.sub(.one).0, n.sub(small(2)).0,
        ]
        scalars += (0..<4).map { _ in
            let value = rng.bigInt()
            return value >= n ? value.sub(n).0 : value
        }
        for s in scalars {
            for t in scalars {
                let expected = referenceAdd(referenceMultiply(g, s), referenceMultiply(base, t))
                assertSame(
                    JacobianPoint.multiplyPublicPair(generatorScalar: s, pointScalar: t, point: jacobian),
                    expected, "\(s.toHex()) \(t.toHex())")
            }
        }
        // P = G、P = -G 让两路加法在同一点上相遇；P 是无穷远点时只剩 [s]G
        let negatedG = JacobianPoint(x: g.x, y: g.y.negate(), z: .one)
        assertSame(
            JacobianPoint.multiplyPublicPair(generatorScalar: small(5), pointScalar: small(5), point: negatedG),
            nil, "5G + 5(-G)")
        assertSame(
            JacobianPoint.multiplyPublicPair(
                generatorScalar: small(5), pointScalar: small(5), point: JacobianPoint(x: g.x, y: g.y, z: .one)),
            referenceMultiply(g, small(10)), "5G + 5G")
        assertSame(
            JacobianPoint.multiplyPublicPair(
                generatorScalar: small(9), pointScalar: small(3), point: JacobianPoint.infinity),
            referenceMultiply(g, small(9)), "9G + 3*inf")
    }

    func testPointAdditionEdgeCases() {
        let generator = ECPoint.generator()
        let negated = generator.negate()
        XCTAssertTrue(generator.add(negated).isInfinity, "P + (-P)")
        XCTAssertEqual(generator.add(generator), generator.twice(), "P + P")
        XCTAssertEqual(generator.add(.infinityPoint()), generator)
        XCTAssertEqual(ECPoint.infinityPoint().add(generator), generator)
        XCTAssertTrue(ECPoint.infinityPoint().add(.infinityPoint()).isInfinity)
        XCTAssertTrue(ECPoint.infinityPoint().twice().isInfinity)
        XCTAssertTrue(ECPoint.infinityPoint().multiply(small(5)).isInfinity)
        XCTAssertTrue(generator.multiply(.zero).isInfinity)
        XCTAssertTrue(generator.multiply(n).isInfinity)
        XCTAssertEqual(generator.multiply(.one), generator)
        XCTAssertEqual(generator.multiply(n.sub(.one).0), negated)

        var jacobian = generator.toJacobian()
        XCTAssertTrue(JacobianPoint.infinity.twice().isInfinity)
        XCTAssertTrue(JacobianPoint(x: g.x, y: .zero, z: .one).twice().isInfinity, "y = 0")
        jacobian = jacobian.twice()
        guard let (x, y) = jacobian.toAffine() else {
            return XCTFail("2G must be finite")
        }
        XCTAssertTrue(ECPoint(x: x, y: y).isOnCurve())
        XCTAssertEqual(ECPoint(x: x, y: y), generator.twice())
        // addAffine 的四种异常情况
        XCTAssertEqual(ECPoint.fromJacobian(JacobianPoint.infinity.addAffine(g.x, g.y)), generator)
        XCTAssertEqual(ECPoint.fromJacobian(generator.toJacobian().addAffine(g.x, g.y)), generator.twice())
        XCTAssertTrue(generator.toJacobian().addAffine(g.x, g.y.negate()).isInfinity)
    }

    /// 验签不求逆的判断必须与 r == (e + x1) mod n 完全一致，包括 x1 落在 [n, p) 和 e >= n 的情况
    func testSignatureMatchesAgreesWithModAdd() {
        var rng = TestRandom(seed: 0x5)
        guard let (x1, _) = JacobianPoint.multiplyGenerator(rng.bigInt()).toAffine() else {
            return XCTFail("point must be finite")
        }
        // 用 Z = 任意值表示同一点，确认判断与 Z 无关
        let z = FpElement(rng.bigInt())
        func point(withAffineX x: BigInt256) -> JacobianPoint {
            let affineX = FpElement(unchecked: x)
            return JacobianPoint(x: affineX.multiply(z.square()), y: .one, z: z)
        }
        let p = SM2Curve.p
        var xs: [BigInt256] = [
            x1.value, .zero, .one, n, n.add(.one).0, n.sub(.one).0, p.sub(.one).0, p.sub(small(2)).0,
        ]
        var es: [BigInt256] = [
            .zero, .one, n, n.add(.one).0, n.sub(.one).0, p, BigInt256(.max, .max, .max, .max),
            BigInt256(.max - 1, .max, .max, .max),
        ]
        for _ in 0..<20 {
            xs.append(FpElement(rng.bigInt()).value)
            es.append(rng.bigInt())
        }
        var matches = 0
        for x in xs {
            for e in es {
                let modulus = ReferenceBigInt(n)
                let sum = (ReferenceBigInt(e) + ReferenceBigInt(x)) % modulus
                let expected = sum.bigInt256
                // 真实 r，以及不同于真实值的 r
                // 后两个是快捷判断的陷阱：x + p - n + e 让候选值 x + p 与 x 模 p 同余，但模 n 不同余；
                // x + e - n 则是未完全约减时会出现的值
                let candidates: [BigInt256] = [
                    expected, expected.add(.one).0, expected.sub(.one).0, n.sub(.one).0, .one,
                    x.add(p).0.sub(n).0.add(e).0, x.add(e).0.sub(n).0,
                ]
                for r in candidates where !r.isZero && r < n {
                    let baseline = expected == r
                    XCTAssertEqual(
                        SM2.signatureMatches(point: point(withAffineX: x), r: r, e: e), baseline,
                        "x=\(x.toHex()) e=\(e.toHex()) r=\(r.toHex())")
                    matches += baseline ? 1 : 0
                }
            }
        }
        XCTAssertGreaterThan(matches, 100)
    }

    func testGeneratorTablesAreConsistent() {
        let comb = GeneratorTables.comb.pointer
        func entry(_ pointer: UnsafePointer<UInt64>, _ index: Int) -> Affine {
            let e = pointer + index * 8
            return Affine(
                x: FpElement(unchecked: BigInt256(e[0], e[1], e[2], e[3])),
                y: FpElement(unchecked: BigInt256(e[4], e[5], e[6], e[7])))
        }
        // 抽查：第0、1、最后一个窗口的头尾项
        XCTAssertEqual(entry(comb, 0), g)
        XCTAssertEqual(entry(comb, 31), referenceMultiply(g, small(32)))
        XCTAssertEqual(entry(comb, 32), referenceMultiply(g, small(64)))
        XCTAssertEqual(entry(comb, 32 + 2), referenceMultiply(g, small(3 * 64)))
        XCTAssertEqual(
            entry(comb, 42 * 32), referenceMultiply(g, BigInt256(0, 0, 0, UInt64(1) << 60)), "2^252 G")

        let odd = GeneratorTables.oddMultiples.pointer
        XCTAssertEqual(entry(odd, 0), g)
        XCTAssertEqual(entry(odd, 1), referenceMultiply(g, small(3)))
        XCTAssertEqual(entry(odd, 63), referenceMultiply(g, small(127)))
    }

    func testEncodingRoundTrips() {
        let generator = ECPoint.generator()
        XCTAssertEqual(ECPoint.fromEncoded(generator.toEncoded()), generator)
        XCTAssertEqual(ECPoint.fromHexEncoded(generator.toHexEncoded()), generator)
        XCTAssertTrue(ECPoint.fromHexEncoded("0x" + generator.toHexEncoded()).isInfinity, "0x prefix is not canonical")
        XCTAssertEqual(ECPoint.infinityPoint().toEncoded(), [0])
        XCTAssertTrue(ECPoint.fromEncoded([]).isInfinity)
        XCTAssertEqual(SM2.decodePoint(generator.toHexEncoded()), generator)
    }
}

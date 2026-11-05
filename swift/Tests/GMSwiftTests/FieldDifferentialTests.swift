import XCTest

@testable import GMSwift

/// 域和标量运算与 ReferenceBigInt 的差分测试
final class FieldDifferentialTests: XCTestCase {
    private let p = ReferenceBigInt(SM2Curve.p)
    private let n = ReferenceBigInt(SM2Curve.n)

    private func samples(seed: UInt64, random: Int) -> [BigInt256] {
        var rng = TestRandom(seed: seed)
        return EdgeValues.all + (0..<random).map { _ in rng.bigInt() }
    }

    private func wide(_ value: ReferenceBigInt) -> Wide512 {
        let w = value.words + [UInt32](repeating: 0, count: 16 - value.words.count)
        func limb(_ i: Int) -> UInt64 { return UInt64(w[i * 2]) | UInt64(w[i * 2 + 1]) << 32 }
        return (limb(0), limb(1), limb(2), limb(3), limb(4), limb(5), limb(6), limb(7))
    }

    func testMultiplyAndSquareMatchReference() {
        let values = samples(seed: 0x1111, random: 12)
        for a in values {
            XCTAssertEqual(ReferenceBigInt(a.square()), ReferenceBigInt(a) * ReferenceBigInt(a), a.toHex())
            for b in values {
                XCTAssertEqual(ReferenceBigInt(a.mul(b)), ReferenceBigInt(a) * ReferenceBigInt(b))
            }
        }
    }

    /// 回归：square() 的交叉项进位必须先从 r_lo 传播到 r_hi，再计算溢出到 r_next。
    /// 这组 limb 模式穷举了让该进位发生的组合。
    func testSquareCrossTermCarryPropagation() {
        let patterns: [UInt64] = [0, 1, 2, .max, .max - 1, 1 << 63, (1 << 63) + 1, 0xFFFF_FFFF, 0xFFFF_FFFF_0000_0000]
        for l0 in patterns {
            for l1 in patterns {
                for l2 in patterns {
                    for l3 in patterns {
                        let value = BigInt256(l0, l1, l2, l3)
                        XCTAssertEqual(
                            ReferenceBigInt(value.square()), ReferenceBigInt(value.mul(value)), value.toHex())
                    }
                }
            }
        }
        // l1*l2 低位与 r3 相加产生进位，同时 l0*l3 的高位已把 r4 顶到全 1
        for value in [
            BigInt256(.max, .max, .max, .max), BigInt256(.max, .max, .max, 0),
            BigInt256(.max, .max - 1, .max, .max - 1),
        ] {
            XCTAssertEqual(ReferenceBigInt(value.square()), ReferenceBigInt(value) * ReferenceBigInt(value))
        }
    }

    func testReduceModPMatchesReference() {
        let values = samples(seed: 0x2222, random: 8)
        for a in values {
            for b in values {
                let product = ReferenceBigInt(a) * ReferenceBigInt(b)
                XCTAssertEqual(ReferenceBigInt(sm2ModReduceP(a.mul(b))), product % p)
            }
        }
    }

    /// 回归：最终约减只有在借位时才能减少 extra。这里直接构造 V = k*p + r。
    func testReduceModPFinalReduction() {
        let remainders: [BigInt256] = [
            .zero, .one, BigInt256(2, 0, 0, 0), SM2Curve.p.sub(.one).0, SM2Curve.p.shiftRight1(),
        ]
        for k in 0..<40 {
            for r in remainders {
                let value = p * ReferenceBigInt([UInt32(k)]) + ReferenceBigInt(r)
                XCTAssertEqual(sm2ModReduceP(wide(value)), r, "k=\(k) r=\(r.toHex())")
            }
        }
        // 2^256 的倍数附近：extra > 0 而低256位小于 p，不发生借位的情况
        let twoTo256 = ReferenceBigInt([0, 0, 0, 0, 0, 0, 0, 0, 1])
        for k in 1..<40 {
            for low in [BigInt256.zero, .one, SM2Curve.p.sub(.one).0, SM2Curve.p] {
                let value = twoTo256 * ReferenceBigInt([UInt32(k)]) + ReferenceBigInt(low)
                XCTAssertEqual(ReferenceBigInt(sm2ModReduceP(wide(value))), value % p)
            }
        }
    }

    /// 每个32位字取极值，最大化正负系数和进位
    func testReduceModPExtremeWords() {
        var rng = TestRandom(seed: 0x3333)
        let extremes: [UInt64] = [0, 1, 0xFFFF_FFFE, 0xFFFF_FFFF]
        for _ in 0..<1500 {
            func limb() -> UInt64 {
                let low = extremes[Int(rng.next() >> 40) % 4]
                let high = extremes[Int(rng.next() >> 40) % 4]
                return low | high << 32
            }
            let value: Wide512 = (limb(), limb(), limb(), limb(), limb(), limb(), limb(), limb())
            let reduced = sm2ModReduceP(value)
            XCTAssertEqual(ReferenceBigInt(reduced), ReferenceBigInt(value) % p)
            XCTAssertTrue(reduced < SM2Curve.p)
        }
        let top: Wide512 = (.max, .max, .max, .max, .max, .max, .max, .max)
        XCTAssertEqual(ReferenceBigInt(sm2ModReduceP(top)), ReferenceBigInt(top) % p)
    }

    func testReduceModNMatchesReference() {
        var rng = TestRandom(seed: 0x4444)
        let top: Wide512 = (.max, .max, .max, .max, .max, .max, .max, .max)
        var values: [Wide512] = [top, (0, 0, 0, 0, 0, 0, 0, 0), (1, 0, 0, 0, 0, 0, 0, 0)]
        values += EdgeValues.all.map { $0.mul($0) }
        values += (0..<400).map { _ in
            (rng.next(), rng.next(), rng.next(), rng.next(), rng.next(), rng.next(), rng.next(), rng.next())
        }
        for value in values {
            let reduced = sm2ModReduceN(value)
            XCTAssertEqual(ReferenceBigInt(reduced), ReferenceBigInt(value) % n)
            XCTAssertTrue(reduced < SM2Curve.n)
        }
    }

    func testModularAddSubMatchReference() {
        let values = samples(seed: 0x5555, random: 10)
        for modulus in [SM2Curve.p, SM2Curve.n] {
            let m = ReferenceBigInt(modulus)
            let reduced = values.map { (ReferenceBigInt($0) % m).bigInt256 }
            for a in reduced {
                for b in reduced {
                    let ra = ReferenceBigInt(a)
                    let rb = ReferenceBigInt(b)
                    XCTAssertEqual(ReferenceBigInt(a.modAdd(b, modulus)), (ra + rb) % m)
                    XCTAssertEqual(ReferenceBigInt(a.modSub(b, modulus)), (ra + m - rb) % m)
                    XCTAssertEqual(ReferenceBigInt(a.modMul(b, modulus)), (ra * rb) % m)
                }
                XCTAssertEqual(ReferenceBigInt(a.modSquare(modulus)), (ReferenceBigInt(a) * ReferenceBigInt(a)) % m)
            }
        }
    }

    func testFieldElementOperations() {
        let values = samples(seed: 0x6666, random: 10).map { FpElement($0) }
        for a in values {
            XCTAssertTrue(a.value < SM2Curve.p)
            let ra = ReferenceBigInt(a.value)
            XCTAssertEqual(ReferenceBigInt(a.negate().value), (p - ra) % p)
            XCTAssertEqual(ReferenceBigInt(a.double().value), (ra + ra) % p)
            XCTAssertEqual(ReferenceBigInt(a.triple().value), (ra + ra + ra) % p)
            XCTAssertEqual(ReferenceBigInt(a.square().value), (ra * ra) % p)
            for b in values {
                let rb = ReferenceBigInt(b.value)
                XCTAssertEqual(ReferenceBigInt(a.add(b).value), (ra + rb) % p)
                XCTAssertEqual(ReferenceBigInt(a.subtract(b).value), (ra + p - rb) % p)
                XCTAssertEqual(ReferenceBigInt(a.multiply(b).value), (ra * rb) % p)
            }
        }
    }

    func testInversionMatchesFermat() {
        var rng = TestRandom(seed: 0x7777)
        let exponentP = SM2Curve.p.sub(BigInt256(2, 0, 0, 0)).0
        let exponentN = SM2Curve.n.sub(BigInt256(2, 0, 0, 0)).0
        let values =
            [BigInt256.one, BigInt256(2, 0, 0, 0), SM2Curve.p.sub(.one).0, SM2Curve.n.sub(.one).0]
            + (0..<3).map { _ in rng.bigInt() }
        for value in values {
            let a = ReferenceBigInt(value)
            XCTAssertEqual(ReferenceBigInt(value.modInverse(SM2Curve.p)), (a % p).power(exponentP, modulus: p))
            XCTAssertEqual(ReferenceBigInt(value.modInverse(SM2Curve.n)), (a % n).power(exponentN, modulus: n))
        }
        for _ in 0..<100 {
            let value = rng.bigInt()
            XCTAssertEqual(value.modMul(value.modInverse(SM2Curve.p), SM2Curve.p), .one)
            XCTAssertEqual(value.modMul(value.modInverse(SM2Curve.n), SM2Curve.n), .one)
            let element = FpElement(value)
            XCTAssertEqual(element.multiply(element.invert()), FpElement.one)
        }
        // 模数的倍数求逆得到 0（签名中 d = n - 1 的边界依赖这一点）
        XCTAssertEqual(SM2Curve.p.modInverse(SM2Curve.p), .zero)
        XCTAssertEqual(SM2Curve.n.modInverse(SM2Curve.n), .zero)
    }

    /// 通用路径（p、n 以外的模数）。提交 3397c6d 的 modReduce512 在模数很小、移位量 >= 320 时不做约减，结果不小于模数。
    func testGenericModulus() {
        var rng = TestRandom(seed: 0x8888)
        let moduli = [
            BigInt256(7, 0, 0, 0), BigInt256(0x10001, 0, 0, 0), BigInt256(.max, 3, 0, 0), BigInt256(5, 0, 0, 1 << 60),
        ]
        for modulus in moduli {
            let m = ReferenceBigInt(modulus)
            for _ in 0..<40 {
                let a = rng.bigInt()
                let b = rng.bigInt()
                XCTAssertEqual(ReferenceBigInt(a.modMul(b, modulus)), (ReferenceBigInt(a) * ReferenceBigInt(b)) % m)
            }
        }
        XCTAssertEqual(BigInt256.modReduce512((0, 0, 0, 0, 0, 0, 0, 0), .zero), .zero)
    }

    func testBitsAndSerialization() {
        for value in samples(seed: 0x9999, random: 20) {
            XCTAssertEqual(BigInt256.fromHex(value.toHex()), value)
            XCTAssertEqual(BigInt256.fromHex(value.toHexLower()), value)
            XCTAssertEqual(BigInt256.fromBEBytes(value.toBEBytes()), value)
            let half = ReferenceBigInt(value.shiftRight1())
            XCTAssertEqual(half + half + ReferenceBigInt([UInt32(value.l0 & 1)]), ReferenceBigInt(value))
            for bit in stride(from: 0, to: 256, by: 17) {
                let expected = (value.limb(bit / 64) >> UInt64(bit % 64)) & 1
                XCTAssertEqual(value.getBit(bit), expected == 1)
                XCTAssertEqual(value.bits(from: bit) & 1, expected)
            }
            XCTAssertFalse(value.getBit(256))
        }
    }

    func testFromHexUnusualInput() {
        XCTAssertEqual(BigInt256.fromHex("0xAB"), BigInt256(0xAB, 0, 0, 0))
        XCTAssertEqual(BigInt256.fromHex("0XabC"), BigInt256(0xABC, 0, 0, 0))
        XCTAssertEqual(BigInt256.fromHex(""), .zero)
        XCTAssertEqual(BigInt256.fromHex("F"), BigInt256(0xF, 0, 0, 0))
        XCTAssertEqual(BigInt256.fromHex(String(repeating: "F", count: 64)), BigInt256(.max, .max, .max, .max))
        XCTAssertEqual(BigInt256.fromBEBytes([]), .zero)
        XCTAssertEqual(BigInt256.fromBEBytes([1, 2]), BigInt256(0x102, 0, 0, 0))
        XCTAssertEqual(BigInt256.fromBEBytes([UInt8](repeating: 9, count: 33) + [1]).l0 & 0xFF, 1)
    }

    /// 曾经会触发数组越界陷阱（超长）或把无效字符当作 0（部分解析）的输入：现在一律得到 0，不陷入陷阱
    func testFromHexInvalidInputReturnsZero() {
        let invalid = [
            "zz", "z1", "1z", "é1", "\r\n12", "12 34", "+1", "-1", "0x", "0xzz", "\u{1F600}",
            String(repeating: "F", count: 65), "0x" + String(repeating: "F", count: 65),
            String(repeating: "1", count: 100_000), String(repeating: "é", count: 64),
        ]
        for text in invalid {
            XCTAssertEqual(BigInt256.fromHex(text), .zero, text.debugDescription)
            XCTAssertNil(BigInt256(hex: text), text.debugDescription)
        }
        XCTAssertNil(BigInt256(hex: ""))
        XCTAssertNil(BigInt256(hex: "1"))
        XCTAssertNil(BigInt256(hex: String(repeating: "1", count: 63)))
        XCTAssertEqual(
            BigInt256(hex: String(repeating: "A", count: 64)), BigInt256(hex: String(repeating: "a", count: 64)))
    }

    func testInversionOfZeroDoesNotTrap() {
        XCTAssertEqual(BigInt256.zero.modInverse(SM2Curve.p), .zero)
        XCTAssertEqual(BigInt256.zero.modInverse(SM2Curve.n), .zero)
        XCTAssertEqual(BigInt256.zero.modInverse(BigInt256(7, 0, 0, 0)), .zero)
        XCTAssertEqual(FpElement.zero.invert(), .zero)
        XCTAssertEqual(BigInt256.modReduce512((1, 0, 0, 0, 0, 0, 0, 0), .zero), .zero)
    }

    func testHexEncodingAgainstByteLoop() {
        var rng = TestRandom(seed: 0xAAAA)
        let hexLower = Array("0123456789abcdef".utf8)
        for length in 0..<40 {
            let bytes = rng.bytes(length)
            let expected = String(
                decoding: bytes.flatMap { [hexLower[Int($0 >> 4)], hexLower[Int($0 & 15)]] }, as: UTF8.self)
            XCTAssertEqual(Hex.encode(bytes), expected)
            XCTAssertEqual(Hex.encode(bytes, gap: Hex.uppercaseGap), expected.uppercased())
            XCTAssertEqual(Hex.decodeStrict(expected), bytes)
            XCTAssertEqual(Hex.decodeStrict(expected.uppercased()), bytes)
        }
        let everyByte = (0...255).map { UInt8($0) }
        XCTAssertEqual(Hex.decodeStrict(Hex.encode(everyByte)), everyByte)
        for invalid in ["0", "abc", "zz", "g0", "0g", "/0", ":0", "@0", "G0", "`0", "é1", "+f"] {
            XCTAssertNil(Hex.decodeStrict(invalid), invalid)
        }
        XCTAssertEqual(Hex.decodeStrict(""), [])
    }
}

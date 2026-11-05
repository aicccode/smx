// SM2 曲线常量与素数域 Fp 运算。
// 域运算全部用掩码实现，不含按数据分支（Swift 不提供恒定时间保证，这是源码层面所能做到的上限）。

// MARK: - SM2曲线参数

enum SM2Curve {
    /// 素数 p = 2^256 - 2^224 - 2^96 + 2^64 - 1
    @inline(__always)
    static var p: BigInt256 {
        return BigInt256(0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_0000_0000, 0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFE_FFFF_FFFF)
    }

    /// 曲线参数 a = p - 3
    @inline(__always)
    static var a: BigInt256 {
        return BigInt256(0xFFFF_FFFF_FFFF_FFFC, 0xFFFF_FFFF_0000_0000, 0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFE_FFFF_FFFF)
    }

    /// 曲线参数 b
    @inline(__always)
    static var b: BigInt256 {
        return BigInt256(0xDDBC_BD41_4D94_0E93, 0xF397_89F5_15AB_8F92, 0x4D5A_9E4B_CF65_09A7, 0x28E9_FA9E_9D9F_5E34)
    }

    /// 曲线阶 n
    @inline(__always)
    static var n: BigInt256 {
        return BigInt256(0x53BB_F409_39D5_4123, 0x7203_DF6B_21C6_052B, 0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFE_FFFF_FFFF)
    }

    /// 基点 G 的 x 坐标
    @inline(__always)
    static var gx: BigInt256 {
        return BigInt256(0x715A_4589_334C_74C7, 0x8FE3_0BBF_F266_0BE1, 0x5F99_0446_6A39_C994, 0x32C4_AE2C_1F19_8119)
    }

    /// 基点 G 的 y 坐标
    @inline(__always)
    static var gy: BigInt256 {
        return BigInt256(0x02DF_32E5_2139_F0A0, 0xD0A9_877C_C62A_4740, 0x59BD_CEE3_6B69_2153, 0xBC37_36A2_F4F6_779C)
    }
}

/// 既有测试使用的名字，保留。
// swift-format-ignore: AlwaysUseLowerCamelCase
var SM2_P: BigInt256 { return SM2Curve.p }

// MARK: - SM2素数域快速模约减

/// SM2素数域快速模约减（恒定时间）
/// 输入：任意512位值（8个UInt64，小端序）；输出：value mod p，取值在 [0, p)
///
/// 用32位字 c15..c0 表示输入，利用 2^256 ≡ 2^224 + 2^96 - 2^64 + 1 (mod p)，
/// 递归替换 2^(32*k) (k>=8) 为低阶项，得到完整的系数表：
///   c8:  w0(+1) w2(-1) w3(+1) w7(+1)
///   c9:  w0(+1) w1(+1) w2(-1) w4(+1) w7(+1)
///   c10: w0(+1) w1(+1) w5(+1) w7(+1)
///   c11: w0(+1) w1(+1) w3(+1) w6(+1) w7(+1)
///   c12: w0(+1) w1(+1) w3(+1) w4(+1) w7(+2)
///   c13: w0(+2) w1(+1) w2(-1) w3(+2) w4(+1) w5(+1) w7(+2)
///   c14: w0(+2) w1(+2) w2(-1) w3(+1) w4(+2) w5(+1) w6(+1) w7(+2)
///   c15: w0(+2) w1(+2) w3(+1) w4(+1) w5(+2) w6(+1) w7(+3)
@inline(__always)
func sm2ModReduceP(_ v: Wide512) -> BigInt256 {
    let low: UInt64 = 0xFFFF_FFFF
    let c0 = Int64(truncatingIfNeeded: v.0 & low)
    let c1 = Int64(truncatingIfNeeded: v.0 &>> 32)
    let c2 = Int64(truncatingIfNeeded: v.1 & low)
    let c3 = Int64(truncatingIfNeeded: v.1 &>> 32)
    let c4 = Int64(truncatingIfNeeded: v.2 & low)
    let c5 = Int64(truncatingIfNeeded: v.2 &>> 32)
    let c6 = Int64(truncatingIfNeeded: v.3 & low)
    let c7 = Int64(truncatingIfNeeded: v.3 &>> 32)
    let c8 = Int64(truncatingIfNeeded: v.4 & low)
    let c9 = Int64(truncatingIfNeeded: v.4 &>> 32)
    let c10 = Int64(truncatingIfNeeded: v.5 & low)
    let c11 = Int64(truncatingIfNeeded: v.5 &>> 32)
    let c12 = Int64(truncatingIfNeeded: v.6 & low)
    let c13 = Int64(truncatingIfNeeded: v.6 &>> 32)
    let c14 = Int64(truncatingIfNeeded: v.7 & low)
    let c15 = Int64(truncatingIfNeeded: v.7 &>> 32)

    // 提取公共子表达式。每个 t[i] 再加上 p 的对应32位字，保证整体非负（负项最多约 -2^98）。
    let word: Int64 = 0xFFFF_FFFF
    let s1415 = c14 &+ c15
    let s1213 = c12 &+ c13
    let s91011 = c9 &+ c10 &+ c11
    let t0 = word &+ c0 &+ c8 &+ s91011 &+ c12 &+ ((c13 &+ s1415) &<< 1)
    let t1 = word &+ c1 &+ s91011 &+ s1213 &+ ((s1415) &<< 1)
    let t2 = c2 &- c8 &- c9 &- c13 &- c14
    let t3 = word &+ c3 &+ c8 &+ c11 &+ s1213 &+ c13 &+ s1415
    let t4 = word &+ c4 &+ c9 &+ s1213 &+ c14 &+ s1415
    let t5 = word &+ c5 &+ c10 &+ c13 &+ s1415 &+ c15
    let t6 = word &+ c6 &+ c11 &+ s1415
    let t7 = (word &- 1) &+ c7 &+ c8 &+ s91011 &+ ((s1213 &+ s1415) &<< 1) &+ c15

    // 进位传播（算术右移实现有符号进位），不用分支
    let u1 = t1 &+ (t0 &>> 32)
    let u2 = t2 &+ (u1 &>> 32)
    let u3 = t3 &+ (u2 &>> 32)
    let u4 = t4 &+ (u3 &>> 32)
    let u5 = t5 &+ (u4 &>> 32)
    let u6 = t6 &+ (u5 &>> 32)
    let u7 = t7 &+ (u6 &>> 32)

    let r0 = UInt64(truncatingIfNeeded: t0) & low | (UInt64(truncatingIfNeeded: u1) &<< 32)
    let r1 = UInt64(truncatingIfNeeded: u2) & low | (UInt64(truncatingIfNeeded: u3) &<< 32)
    let r2 = UInt64(truncatingIfNeeded: u4) & low | (UInt64(truncatingIfNeeded: u5) &<< 32)
    let r3 = UInt64(truncatingIfNeeded: u6) & low | (UInt64(truncatingIfNeeded: u7) &<< 32)

    // 真实值 V = r + extra * 2^256，0 <= extra <= 15。再折叠一次：2^256 ≡ c = 2^224 + 2^96 - 2^64 + 1
    let extra = UInt64(truncatingIfNeeded: u7 &>> 32)
    var carry: UInt64 = 0
    let f0 = addWithCarry(r0, extra, &carry)
    let f1 = addWithCarry(r1, (extra &<< 32) &- extra, &carry)
    let f2 = addWithCarry(r2, 0, &carry)
    let f3 = addWithCarry(r3, extra &<< 32, &carry)

    // 上一步若再次溢出，结果必然很小，这次折叠不会继续溢出
    let overflow = carry
    carry = 0
    let g0 = addWithCarry(f0, overflow, &carry)
    let g1 = addWithCarry(f1, (overflow &<< 32) &- overflow, &carry)
    let g2 = addWithCarry(f2, 0, &carry)
    let g3 = addWithCarry(f3, overflow &<< 32, &carry)

    // 此时 value < 2^256 < 2p，最多再减一次 p
    return FpElement.subtractPOnce(BigInt256(g0, g1, g2, g3))
}

/// 阶 n 没有可利用的稀疏结构，走 Montgomery 约减（见 ScalarField）
@inline(__always)
func sm2ModReduceN(_ v: Wide512) -> BigInt256 {
    return ScalarField.reduce(v)
}

// MARK: - 素数域元素（使用SM2快速约减）

public struct FpElement: Equatable {
    public var value: BigInt256

    init(_ value: BigInt256) {
        self.value = FpElement.subtractPOnce(value)
    }

    // 内部构造，不检查范围（已知在域内）
    @inline(__always)
    init(unchecked value: BigInt256) {
        self.value = value
    }

    /// value >= p 时减去一次 p
    @inline(__always)
    static func subtractPOnce(_ value: BigInt256) -> BigInt256 {
        let (reduced, borrow) = value.subtractingWithBorrow(SM2Curve.p)
        return BigInt256.select(zeroMask(borrow), reduced, value)
    }

    static func fromHex(_ hex: String) -> FpElement {
        return FpElement(BigInt256.fromHex(hex))
    }

    static let zero = FpElement(unchecked: BigInt256.zero)
    static let one = FpElement(unchecked: BigInt256.one)

    @inline(__always)
    var isZero: Bool { return value.isZero }

    var isOne: Bool { return value.isOne }

    @inline(__always)
    static func select(_ mask: UInt64, _ a: FpElement, _ b: FpElement) -> FpElement {
        return FpElement(unchecked: BigInt256.select(mask, a.value, b.value))
    }

    @inline(__always)
    func add(_ other: FpElement) -> FpElement {
        return FpElement(unchecked: value.modAdd(other.value, SM2Curve.p))
    }

    @inline(__always)
    func subtract(_ other: FpElement) -> FpElement {
        return FpElement(unchecked: value.modSub(other.value, SM2Curve.p))
    }

    func multiply(_ other: FpElement) -> FpElement {
        return FpElement(unchecked: sm2ModReduceP(value.mul(other.value)))
    }

    func square() -> FpElement {
        return FpElement(unchecked: sm2ModReduceP(value.square()))
    }

    /// 连续平方 count 次
    @inline(__always)
    func square(times count: Int) -> FpElement {
        var result = self
        for _ in 0..<count {
            result = result.square()
        }
        return result
    }

    @inline(__always)
    func negate() -> FpElement {
        // 0 取负仍是 0，用掩码保持规范表示
        let negated = SM2Curve.p.subtractingWithBorrow(value).difference
        return FpElement(unchecked: BigInt256.select(value.isZeroMask, value, negated))
    }

    func invert() -> FpElement {
        if isZero {
            fatalError("Cannot invert zero")
        }
        return invertedUnchecked()
    }

    /// 费马小定理求逆：a^(p-2)，指数是公开常量，使用固定加法链（255次平方 + 15次乘法）。
    /// p-2 的二进制结构：31个1、1个0、128个1、32个0、32个1、30个1、01。
    func invertedUnchecked() -> FpElement {
        let x1 = self
        let x2 = x1.square().multiply(x1)
        let x3 = x2.square().multiply(x1)
        let x6 = x3.square(times: 3).multiply(x3)
        let x12 = x6.square(times: 6).multiply(x6)
        let x15 = x12.square(times: 3).multiply(x3)
        let x30 = x15.square(times: 15).multiply(x15)
        let x31 = x30.square().multiply(x1)
        let x32 = x31.square().multiply(x1)

        var result = x31.square()
        for _ in 0..<4 {
            result = result.square(times: 32).multiply(x32)
        }
        result = result.square(times: 32)
        result = result.square(times: 32).multiply(x32)
        result = result.square(times: 30).multiply(x30)
        return result.square(times: 2).multiply(x1)
    }

    func divide(_ other: FpElement) -> FpElement {
        return multiply(other.invert())
    }

    @inline(__always)
    func double() -> FpElement {
        return add(self)
    }

    @inline(__always)
    func triple() -> FpElement {
        return double().add(self)
    }

    func toBigInt() -> BigInt256 {
        return value
    }

    func toBEBytes() -> [UInt8] {
        return value.toBEBytes()
    }

    func toHex() -> String {
        return value.toHex()
    }
}

// SM2椭圆曲线公钥密码算法实现

import Foundation
#if canImport(Security)
import Security
#endif

// MARK: - SM2曲线参数

/// SM2推荐曲线的素数p
let SM2_P = BigInt256(
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFF00000000,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFEFFFFFFFF
)

/// SM2曲线参数 a
let SM2_A = BigInt256(
    0xFFFFFFFFFFFFFFFC,
    0xFFFFFFFF00000000,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFEFFFFFFFF
)

/// SM2曲线参数 b
let SM2_B = BigInt256(
    0xDDBCBD414D940E93,
    0xF39789F515AB8F92,
    0x4D5A9E4BCF6509A7,
    0x28E9FA9E9D9F5E34
)

/// SM2曲线阶 n
let SM2_N = BigInt256(
    0x53BBF40939D54123,
    0x7203DF6B21C6052B,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFEFFFFFFFF
)

/// SM2基点 G 的 x 坐标
let SM2_GX = BigInt256(
    0x715A4589334C74C7,
    0x8FE30BBFF2660BE1,
    0x5F9904466A39C994,
    0x32C4AE2C1F198119
)

/// SM2基点 G 的 y 坐标
let SM2_GY = BigInt256(
    0x02DF32E52139F0A0,
    0xD0A9877CC62A4740,
    0x59BDCEE36B692153,
    0xBC3736A2F4F6779C
)

// MARK: - SM2素数域快速模约减
// SM2 素数 p = 2^256 - 2^224 - 2^96 + 2^64 - 1
// 利用 p 的特殊结构实现快速约减，避免通用的逐位试商

/// SM2素数域快速模约减
/// 输入：512位乘积（8个UInt64，小端序）
/// 输出：result mod p
///
/// SM2 p = FFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_00000000_FFFFFFFF_FFFFFFFF
/// 用32位字表示输入为 c15..c0（大端），利用 2^256 ≡ 2^224 + 2^96 - 2^64 + 1 (mod p)
/// 参考《GMT 0003.1-2012》标准的快速约减公式
@inline(__always)
func sm2ModReduceP(_ v: (UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64)) -> BigInt256 {
    // 将8个UInt64分解为16个UInt32（小端序）
    let c0  = Int64(UInt32(truncatingIfNeeded: v.0))
    let c1  = Int64(v.0 >> 32)
    let c2  = Int64(UInt32(truncatingIfNeeded: v.1))
    let c3  = Int64(v.1 >> 32)
    let c4  = Int64(UInt32(truncatingIfNeeded: v.2))
    let c5  = Int64(v.2 >> 32)
    let c6  = Int64(UInt32(truncatingIfNeeded: v.3))
    let c7  = Int64(v.3 >> 32)
    let c8  = Int64(UInt32(truncatingIfNeeded: v.4))
    let c9  = Int64(v.4 >> 32)
    let c10 = Int64(UInt32(truncatingIfNeeded: v.5))
    let c11 = Int64(v.5 >> 32)
    let c12 = Int64(UInt32(truncatingIfNeeded: v.6))
    let c13 = Int64(v.6 >> 32)
    let c14 = Int64(UInt32(truncatingIfNeeded: v.7))
    let c15 = Int64(v.7 >> 32)

    // SM2快速约减公式
    // p = 2^256 - 2^224 - 2^96 + 2^64 - 1
    // 即 2^256 ≡ 2^224 + 2^96 - 2^64 + 1 (mod p)
    //
    // 通过递归替换 2^(32*k) (k>=8) 为低阶项，得到完整的系数表：
    // c8:  w0(+1) w2(-1) w3(+1) w7(+1)
    // c9:  w0(+1) w1(+1) w2(-1) w4(+1) w7(+1)
    // c10: w0(+1) w1(+1) w5(+1) w7(+1)
    // c11: w0(+1) w1(+1) w3(+1) w6(+1) w7(+1)
    // c12: w0(+1) w1(+1) w3(+1) w4(+1) w7(+2)
    // c13: w0(+2) w1(+1) w2(-1) w3(+2) w4(+1) w5(+1) w7(+2)
    // c14: w0(+2) w1(+2) w2(-1) w3(+1) w4(+2) w5(+1) w6(+1) w7(+2)
    // c15: w0(+2) w1(+2) w3(+1) w4(+1) w5(+2) w6(+1) w7(+3)
    // t7 = c7 + c8 + c9 + c10 + c11 + 2*c12 + 2*c13 + 2*c14 + 3*c15

    var t0 = c0 + c8 + c9 + c10 + c11 + c12 + 2*c13 + 2*c14 + 2*c15
    var t1 = c1 + c9 + c10 + c11 + c12 + c13 + 2*c14 + 2*c15
    var t2 = c2 - c8 - c9 - c13 - c14
    var t3 = c3 + c8 + c11 + c12 + 2*c13 + c14 + c15
    var t4 = c4 + c9 + c12 + c13 + 2*c14 + c15
    var t5 = c5 + c10 + c13 + c14 + 2*c15
    var t6 = c6 + c11 + c14 + c15
    var t7 = c7 + c8 + c9 + c10 + c11 + 2*c12 + 2*c13 + 2*c14 + 3*c15

    // 进位传播（从低到高），确保每个 t[i] 在 [0, 2^32) 范围内
    @inline(__always)
    func propagate(_ lo: inout Int64, _ hi: inout Int64) {
        // 算术右移32位实现有符号的进位/借位传播
        hi += lo >> 32
        lo &= 0xFFFFFFFF
        // 确保 lo >= 0（处理负数取模）
        if lo < 0 {
            lo += 0x100000000
            hi -= 1
        }
    }

    propagate(&t0, &t1)
    propagate(&t1, &t2)
    propagate(&t2, &t3)
    propagate(&t3, &t4)
    propagate(&t4, &t5)
    propagate(&t5, &t6)
    propagate(&t6, &t7)

    var result = BigInt256(
        UInt64(t0) | (UInt64(t1) << 32),
        UInt64(t2) | (UInt64(t3) << 32),
        UInt64(t4) | (UInt64(t5) << 32),
        UInt64(t6) | (UInt64(t7 & 0xFFFFFFFF) << 32)
    )
    var extra = t7 >> 32

    // 处理最终的约减：真实值 V = result + extra * 2^256
    // 每次减去p：V' = V - p，若result < p则borrow使extra减1
    while extra > 0 || (extra == 0 && result >= SM2_P) {
        let (r, borrow) = result.sub(SM2_P)
        result = r
        if borrow { extra -= 1 }
    }
    while extra < 0 {
        let (r, carry) = result.add(SM2_P)
        result = r
        if carry { extra += 1 }
    }

    return result
}

/// SM2阶n的快速模约减不适用特殊结构，使用通用方法
@inline(__always)
func sm2ModReduceN(_ v: (UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64)) -> BigInt256 {
    return BigInt256.modReduce512(v, SM2_N)
}

// MARK: - 素数域元素（使用SM2快速约减）

public struct FpElement: Equatable {
    public var value: BigInt256

    init(_ value: BigInt256) {
        if value >= SM2_P {
            self.value = value.modSub(SM2_P, SM2_P)
        } else {
            self.value = value
        }
    }

    // 内部构造，不检查范围（已知在域内）
    @inline(__always)
    init(unchecked value: BigInt256) {
        self.value = value
    }

    static func fromHex(_ hex: String) -> FpElement {
        return FpElement(BigInt256.fromHex(hex))
    }

    static let zero = FpElement(unchecked: BigInt256.zero)
    static let one = FpElement(unchecked: BigInt256.one)

    var isZero: Bool { return value.isZero }
    var isOne: Bool { return value.isOne }

    @inline(__always)
    func add(_ other: FpElement) -> FpElement {
        return FpElement(unchecked: value.modAdd(other.value, SM2_P))
    }

    @inline(__always)
    func subtract(_ other: FpElement) -> FpElement {
        return FpElement(unchecked: value.modSub(other.value, SM2_P))
    }

    @inline(__always)
    func multiply(_ other: FpElement) -> FpElement {
        let product = value.mul(other.value)
        return FpElement(unchecked: sm2ModReduceP(product))
    }

    @inline(__always)
    func square() -> FpElement {
        let product = value.square()
        return FpElement(unchecked: sm2ModReduceP(product))
    }

    func negate() -> FpElement {
        if isZero { return self }
        return FpElement(unchecked: SM2_P.modSub(value, SM2_P))
    }

    func invert() -> FpElement {
        if isZero { fatalError("Cannot invert zero") }
        return FpElement(unchecked: value.modInverse(SM2_P))
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

// MARK: - Jacobian坐标椭圆曲线点
// 使用Jacobian坐标 (X, Y, Z)，对应仿射坐标 (X/Z^2, Y/Z^3)
// 优势：点加和倍点不需要昂贵的模逆运算

struct JacobianPoint {
    var x: FpElement
    var y: FpElement
    var z: FpElement

    static let infinity = JacobianPoint(x: .one, y: .one, z: .zero)

    var isInfinity: Bool { return z.isZero }

    /// Jacobian坐标点倍点
    /// 参考: "Guide to Elliptic Curve Cryptography" Algorithm 3.21
    /// Cost: 4M + 4S (使用a = p - 3优化)
    @inline(__always)
    func twice() -> JacobianPoint {
        if isInfinity || y.isZero {
            return JacobianPoint.infinity
        }

        let x1 = self.x, y1 = self.y, z1 = self.z

        // SM2 的 a = p - 3，可以利用 3*x1^2 + a*z1^4 = 3*(x1 - z1^2)*(x1 + z1^2)
        let z1sq = z1.square()
        let m = x1.subtract(z1sq).triple().multiply(x1.add(z1sq))

        let y1sq = y1.square()
        let s = x1.multiply(y1sq).double().double()  // 4*x1*y1^2

        let x3 = m.square().subtract(s.double())
        let y1sq_sq = y1sq.square()
        let y3 = m.multiply(s.subtract(x3)).subtract(y1sq_sq.double().double().double())  // m*(s-x3) - 8*y1^4
        let z3 = y1.double().multiply(z1)

        return JacobianPoint(x: x3, y: y3, z: z3)
    }

    /// Jacobian坐标点加法（混合加法，Q是仿射坐标）
    /// Cost: 8M + 3S（比完整Jacobian加法更快）
    @inline(__always)
    func addAffine(_ qx: FpElement, _ qy: FpElement) -> JacobianPoint {
        if isInfinity {
            return JacobianPoint(x: qx, y: qy, z: .one)
        }

        let z1sq = z.square()
        let u2 = qx.multiply(z1sq)
        let s2 = qy.multiply(z1sq).multiply(z)

        let h = u2.subtract(x)
        let r = s2.subtract(y)

        if h.isZero {
            if r.isZero {
                return self.twice()
            }
            return JacobianPoint.infinity
        }

        let h2 = h.square()
        let h3 = h.multiply(h2)
        let u1h2 = x.multiply(h2)

        let x3 = r.square().subtract(h3).subtract(u1h2.double())
        let y3 = r.multiply(u1h2.subtract(x3)).subtract(y.multiply(h3))
        let z3 = z.multiply(h)

        return JacobianPoint(x: x3, y: y3, z: z3)
    }

    /// Jacobian坐标完整点加法
    /// Cost: 12M + 4S
    func addJacobian(_ other: JacobianPoint) -> JacobianPoint {
        if self.isInfinity { return other }
        if other.isInfinity { return self }

        let z1sq = z.square()
        let z2sq = other.z.square()

        let u1 = x.multiply(z2sq)
        let u2 = other.x.multiply(z1sq)
        let s1 = y.multiply(z2sq).multiply(other.z)
        let s2 = other.y.multiply(z1sq).multiply(z)

        let h = u2.subtract(u1)
        let r = s2.subtract(s1)

        if h.isZero {
            if r.isZero {
                return self.twice()
            }
            return JacobianPoint.infinity
        }

        let h2 = h.square()
        let h3 = h.multiply(h2)
        let u1h2 = u1.multiply(h2)

        let x3 = r.square().subtract(h3).subtract(u1h2.double())
        let y3 = r.multiply(u1h2.subtract(x3)).subtract(s1.multiply(h3))
        let z3 = z.multiply(other.z).multiply(h)

        return JacobianPoint(x: x3, y: y3, z: z3)
    }

    /// 转换到仿射坐标（需要一次模逆）
    func toAffine() -> (FpElement, FpElement)? {
        if isInfinity { return nil }
        let zInv = z.invert()
        let zInv2 = zInv.square()
        let zInv3 = zInv2.multiply(zInv)
        let ax = x.multiply(zInv2)
        let ay = y.multiply(zInv3)
        return (ax, ay)
    }

    /// 标量乘法（使用wNAF或简单的double-and-add）
    func multiply(_ k: BigInt256) -> JacobianPoint {
        if k.isZero || isInfinity {
            return JacobianPoint.infinity
        }
        if k.isOne {
            return self
        }

        // 转为仿射坐标用于混合加法（如果已经是仿射的话更快）
        guard let (ax, ay) = self.toAffine() else {
            return JacobianPoint.infinity
        }

        var result = JacobianPoint.infinity
        let bitLen = k.bitLength

        // 从最高位到最低位的double-and-add（比从低到高更适合混合加法）
        for i in stride(from: bitLen - 1, through: 0, by: -1) {
            result = result.twice()
            if k.getBit(i) {
                result = result.addAffine(ax, ay)
            }
        }

        return result
    }
}

// MARK: - 椭圆曲线点（仿射坐标，公开接口）

public class ECPoint: Equatable {
    public var x: FpElement
    public var y: FpElement
    var infinity: Bool

    init(x: FpElement, y: FpElement) {
        self.x = x
        self.y = y
        self.infinity = false
    }

    init(infinity: Bool) {
        self.x = FpElement.zero
        self.y = FpElement.zero
        self.infinity = true
    }

    public static func infinityPoint() -> ECPoint {
        return ECPoint(infinity: true)
    }

    public static func generator() -> ECPoint {
        return ECPoint(x: FpElement(SM2_GX), y: FpElement(SM2_GY))
    }

    public var isInfinity: Bool { return infinity }

    public static func fromHex(xHex: String, yHex: String) -> ECPoint {
        return ECPoint(x: FpElement.fromHex(xHex), y: FpElement.fromHex(yHex))
    }

    public static func fromEncoded(_ data: [UInt8]) -> ECPoint {
        if data.isEmpty {
            return ECPoint.infinityPoint()
        }
        if data[0] != 0x04 {
            fatalError("Only uncompressed point format is supported")
        }
        if data.count != 65 {
            fatalError("Invalid point encoding length")
        }
        let x = FpElement(BigInt256.fromBEBytes(Array(data[1..<33])))
        let y = FpElement(BigInt256.fromBEBytes(Array(data[33..<65])))
        return ECPoint(x: x, y: y)
    }

    public static func fromHexEncoded(_ hex: String) -> ECPoint {
        var hexStr = hex
        if hexStr.hasPrefix("0x") || hexStr.hasPrefix("0X") {
            hexStr = String(hexStr.dropFirst(2))
        }
        var bytes = [UInt8]()
        var index = hexStr.startIndex
        while index < hexStr.endIndex {
            let nextIndex = hexStr.index(index, offsetBy: 2, limitedBy: hexStr.endIndex) ?? hexStr.endIndex
            if let byte = UInt8(hexStr[index..<nextIndex], radix: 16) {
                bytes.append(byte)
            }
            index = nextIndex
        }
        return fromEncoded(bytes)
    }

    public func toEncoded() -> [UInt8] {
        if infinity {
            return [0x00]
        }
        var result = [UInt8]()
        result.append(0x04)
        result.append(contentsOf: x.toBEBytes())
        result.append(contentsOf: y.toBEBytes())
        return result
    }

    public func toHexEncoded() -> String {
        let bytes = toEncoded()
        return bytes.map { String(format: "%02x", $0) }.joined()
    }

    func negate() -> ECPoint {
        if infinity {
            return ECPoint.infinityPoint()
        }
        return ECPoint(x: x, y: y.negate())
    }

    // 转换为Jacobian坐标
    func toJacobian() -> JacobianPoint {
        if infinity { return JacobianPoint.infinity }
        return JacobianPoint(x: x, y: y, z: .one)
    }

    // 从Jacobian坐标转换回仿射坐标
    static func fromJacobian(_ jp: JacobianPoint) -> ECPoint {
        guard let (ax, ay) = jp.toAffine() else {
            return ECPoint.infinityPoint()
        }
        return ECPoint(x: ax, y: ay)
    }

    func add(_ other: ECPoint) -> ECPoint {
        if self.infinity { return other }
        if other.infinity { return self }

        // 使用Jacobian加法
        let jp1 = self.toJacobian()
        let jp2 = other.toJacobian()
        let result = jp1.addJacobian(jp2)
        return ECPoint.fromJacobian(result)
    }

    func twice() -> ECPoint {
        if infinity { return self }
        let jp = self.toJacobian()
        let result = jp.twice()
        return ECPoint.fromJacobian(result)
    }

    func subtract(_ other: ECPoint) -> ECPoint {
        return add(other.negate())
    }

    func multiply(_ k: BigInt256) -> ECPoint {
        if k.isZero || infinity {
            return ECPoint.infinityPoint()
        }
        if k.isOne {
            return self
        }

        // 使用Jacobian坐标进行标量乘法，仅最后转换回仿射坐标
        let jp = self.toJacobian()
        let result = jp.multiply(k)
        return ECPoint.fromJacobian(result)
    }

    func isOnCurve() -> Bool {
        if infinity {
            return true
        }

        // y^2 = x^3 + a*x + b
        let lhs = y.square()
        let rhs = x.square().add(FpElement(SM2_A)).multiply(x).add(FpElement(SM2_B))
        return lhs == rhs
    }

    public static func == (lhs: ECPoint, rhs: ECPoint) -> Bool {
        if lhs.infinity && rhs.infinity {
            return true
        }
        if lhs.infinity || rhs.infinity {
            return false
        }
        return lhs.x == rhs.x && lhs.y == rhs.y
    }
}

// MARK: - SM2密钥交换参数

public class SM2KeySwapParams {
    public var sa: String?
    public var sb: String?
    public var ka: String?
    public var kb: String?
    public var v: ECPoint?
    public var za: [UInt8]?
    public var zb: [UInt8]?
    public var success: Bool = false
    public var message: String?
}

// MARK: - SM2主类

public class SM2 {

    // MARK: - 密钥对生成

    public static func genKeyPair() -> (privateKey: String, publicKey: String) {
        while true {
            let privateKey = randomBigInt()

            if privateKey.isZero || privateKey >= SM2_N {
                continue
            }

            let publicKey = ECPoint.generator().multiply(privateKey)

            let priHex = privateKey.toHex()
            let pubHex = publicKey.toHexEncoded()

            if priHex.count == 64 && pubHex.count == 130 {
                return (priHex, pubHex)
            }
        }
    }

    // MARK: - 加密

    public static func encrypt(_ plaintext: String, publicKey: String) throws -> String {
        let message = Array(plaintext.utf8)
        if message.isEmpty {
            throw SM2Error.invalidInput("Plaintext cannot be empty")
        }

        let pubPoint = ECPoint.fromHexEncoded(publicKey)
        if !pubPoint.isOnCurve() {
            throw SM2Error.invalidKey("Invalid public key")
        }

        while true {
            let k = randomBigInt()
            if k.isZero || k >= SM2_N {
                continue
            }

            // C1 = [k]G
            let c1 = ECPoint.generator().multiply(k)

            // P2 = [k]PB
            let p2 = pubPoint.multiply(k)
            if p2.isInfinity {
                continue
            }

            // KDF
            let key = kdf(keylen: message.count, p2: p2)

            if key.allSatisfy({ $0 == 0 }) {
                continue
            }

            // C2 = M XOR t
            var c2 = message
            for i in 0..<c2.count {
                c2[i] ^= key[i]
            }

            // C3 = SM3(x2 || M || y2)
            let sm3 = SM3()
            _ = sm3.update(p2.x.toBEBytes())
            _ = sm3.update(message)
            _ = sm3.update(p2.y.toBEBytes())
            _ = sm3.finalize()
            let c3 = sm3.getHashBytes()

            // 输出 C1 || C3 || C2
            var result = c1.toHexEncoded()
            result += bytesToHex(c3)
            result += bytesToHex(c2)

            return result
        }
    }

    // MARK: - 解密

    public static func decrypt(_ ciphertext: String, privateKey: String) throws -> String {
        if ciphertext.count < 130 + 64 {
            throw SM2Error.invalidInput("Ciphertext too short")
        }

        // 解析 C1 || C3 || C2
        let c1Hex = String(ciphertext.prefix(130))
        let c3Hex = String(ciphertext.dropFirst(130).prefix(64))
        let c2Hex = String(ciphertext.dropFirst(194))

        let c1 = ECPoint.fromHexEncoded(c1Hex)
        if !c1.isOnCurve() {
            throw SM2Error.invalidInput("Invalid C1 point")
        }

        let c3 = try hexToBytes(c3Hex)
        var c2 = try hexToBytes(c2Hex)

        let d = BigInt256.fromHex(privateKey)

        // P2 = [d]C1
        let p2 = c1.multiply(d)
        if p2.isInfinity {
            throw SM2Error.decryptionFailed("Invalid decryption")
        }

        // KDF
        let key = kdf(keylen: c2.count, p2: p2)

        // M = C2 XOR t
        for i in 0..<c2.count {
            c2[i] ^= key[i]
        }

        // 验证 C3
        let sm3 = SM3()
        _ = sm3.update(p2.x.toBEBytes())
        _ = sm3.update(c2)
        _ = sm3.update(p2.y.toBEBytes())
        _ = sm3.finalize()
        let computedC3 = sm3.getHashBytes()

        if computedC3 != c3 {
            throw SM2Error.decryptionFailed("Decryption verification failed")
        }

        guard let plaintext = String(bytes: c2, encoding: .utf8) else {
            throw SM2Error.decryptionFailed("UTF-8 decode error")
        }

        return plaintext
    }

    // MARK: - 签名

    public static func sign(userId: String, message: String, privateKey: String) throws -> String {
        let d = BigInt256.fromHex(privateKey)
        let publicKey = ECPoint.generator().multiply(d)

        // 计算 Z
        let z = userSM3Z(userId: Array(userId.utf8), publicKey: publicKey)

        // e = SM3(Z || M)
        let sm3 = SM3()
        _ = sm3.update(z)
        _ = sm3.update(Array(message.utf8))
        _ = sm3.finalize()
        let e = BigInt256.fromBEBytes(sm3.getHashBytes())

        while true {
            let k = randomBigInt()
            if k.isZero || k >= SM2_N {
                continue
            }

            // (x1, y1) = [k]G
            let kp = ECPoint.generator().multiply(k)
            let x1 = kp.x.toBigInt()

            // r = (e + x1) mod n
            let r = e.modAdd(x1, SM2_N)
            if r.isZero {
                continue
            }

            // 检查 r + k != n
            let (rk, _) = r.add(k)
            if rk == SM2_N {
                continue
            }

            // s = ((1 + d)^-1 * (k - r*d)) mod n
            let one = BigInt256.one
            let (dPlus1, _) = d.add(one)
            let dPlus1Inv = dPlus1.modInverse(SM2_N)
            let rd = r.modMul(d, SM2_N)
            let kMinusRd = k.modSub(rd, SM2_N)
            let s = kMinusRd.modMul(dPlus1Inv, SM2_N)

            if s.isZero {
                continue
            }

            let rHex = r.toHex()
            let sHex = s.toHex()
            if rHex.count == 64 && sHex.count == 64 {
                return "\(rHex.lowercased())h\(sHex.lowercased())"
            }
        }
    }

    // MARK: - 验签

    public static func verify(userId: String, signature: String, message: String, publicKey: String) -> Bool {
        let parts = signature.split(separator: "h")
        if parts.count != 2 {
            return false
        }

        let r = BigInt256.fromHex(String(parts[0]))
        let s = BigInt256.fromHex(String(parts[1]))

        if r.isZero || r >= SM2_N {
            return false
        }
        if s.isZero || s >= SM2_N {
            return false
        }

        let pubPoint = ECPoint.fromHexEncoded(publicKey)
        if !pubPoint.isOnCurve() {
            return false
        }

        // 计算 Z
        let z = userSM3Z(userId: Array(userId.utf8), publicKey: pubPoint)

        // e = SM3(Z || M)
        let sm3 = SM3()
        _ = sm3.update(z)
        _ = sm3.update(Array(message.utf8))
        _ = sm3.finalize()
        let e = BigInt256.fromBEBytes(sm3.getHashBytes())

        // t = (r + s) mod n
        let t = r.modAdd(s, SM2_N)
        if t.isZero {
            return false
        }

        // (x1, y1) = [s]G + [t]PA
        // 使用Jacobian坐标做双标量乘法
        let gJac = ECPoint.generator().toJacobian()
        let sg = gJac.multiply(s)
        let pubJac = pubPoint.toJacobian()
        let tpa = pubJac.multiply(t)
        let pointJac = sg.addJacobian(tpa)

        guard let (px, _) = pointJac.toAffine() else {
            return false
        }

        // R = (e + x1) mod n
        let computedR = e.modAdd(px.toBigInt(), SM2_N)

        return r == computedR
    }

    // MARK: - 密钥交换协议

    public static func getSb(
        byteLen: Int,
        pA: ECPoint, Ra: ECPoint,
        pB: ECPoint, dB: BigInt256, Rb: ECPoint, rb: BigInt256,
        IDa: String, IDb: String
    ) -> SM2KeySwapParams {
        let result = SM2KeySwapParams()

        // x2_ = 2^w + (x2 & (2^w - 1))
        let x2_ = calcX(Rb.x.toBigInt())

        // tb = (dB + x2_ * rb) mod n
        let tb = calcT(n: SM2_N, r: rb, d: dB, x_: x2_)

        // 验证 Ra 在曲线上
        if !Ra.isOnCurve() {
            result.message = "协商失败，A用户随机公钥不是椭圆曲线倍点"
            return result
        }

        // x1_ = 2^w + (x1 & (2^w - 1))
        let x1_ = calcX(Ra.x.toBigInt())

        // V = [tb](PA + [x1_]RA)
        let v = calcPoint(t: tb, x_: x1_, p: pA, r: Ra)
        if v.isInfinity {
            result.message = "协商失败，V点是无穷远点"
            return result
        }

        let za = userSM3Z(userId: Array(IDa.utf8), publicKey: pA)
        let zb = userSM3Z(userId: Array(IDb.utf8), publicKey: pB)

        let kb = kdfKeySwap(keylen: byteLen, vu: v, za: za, zb: zb)
        let sb = createS(tag: 0x02, vu: v, za: za, zb: zb, ra: Ra, rb: Rb)

        result.sb = bytesToHex(sb)
        result.kb = bytesToHex(kb)
        result.v = v
        result.za = za
        result.zb = zb
        result.success = true

        return result
    }

    public static func getSa(
        byteLen: Int,
        pB: ECPoint, Rb: ECPoint,
        pA: ECPoint, dA: BigInt256, Ra: ECPoint, ra: BigInt256,
        IDa: String, IDb: String,
        Sb: [UInt8]
    ) -> SM2KeySwapParams {
        let result = SM2KeySwapParams()

        // x1_ = 2^w + (x1 & (2^w - 1))
        let x1_ = calcX(Ra.x.toBigInt())

        // ta = (dA + x1_ * ra) mod n
        let ta = calcT(n: SM2_N, r: ra, d: dA, x_: x1_)

        // 验证 Rb 在曲线上
        if !Rb.isOnCurve() {
            result.message = "协商失败，B用户随机公钥不是椭圆曲线倍点"
            return result
        }

        // x2_ = 2^w + (x2 & (2^w - 1))
        let x2_ = calcX(Rb.x.toBigInt())

        // U = [ta](PB + [x2_]RB)
        let u = calcPoint(t: ta, x_: x2_, p: pB, r: Rb)
        if u.isInfinity {
            result.message = "协商失败，U点是无穷远点"
            return result
        }

        let za = userSM3Z(userId: Array(IDa.utf8), publicKey: pA)
        let zb = userSM3Z(userId: Array(IDb.utf8), publicKey: pB)

        let ka = kdfKeySwap(keylen: byteLen, vu: u, za: za, zb: zb)
        let s1 = createS(tag: 0x02, vu: u, za: za, zb: zb, ra: Ra, rb: Rb)

        if s1 != Sb {
            result.message = "协商失败，B用户验证值与A侧计算值不相等"
            return result
        }

        let sa = createS(tag: 0x03, vu: u, za: za, zb: zb, ra: Ra, rb: Rb)

        result.sa = bytesToHex(sa)
        result.ka = bytesToHex(ka)
        result.success = true

        return result
    }

    public static func checkSa(V: ECPoint, Za: [UInt8], Zb: [UInt8], Ra: ECPoint, Rb: ECPoint, Sa: [UInt8]) -> Bool {
        let s2 = createS(tag: 0x03, vu: V, za: Za, zb: Zb, ra: Ra, rb: Rb)
        return s2 == Sa
    }

    // MARK: - 辅助方法

    static func decodePoint(_ hex: String) -> ECPoint {
        return ECPoint.fromHexEncoded(hex)
    }

    static func getPublicKey(_ privateKey: BigInt256) -> ECPoint {
        return ECPoint.generator().multiply(privateKey)
    }

    // MARK: - 内部辅助方法

    private static func randomBigInt() -> BigInt256 {
        var bytes = [UInt8](repeating: 0, count: 32)
        #if canImport(Security)
        _ = SecRandomCopyBytes(kSecRandomDefault, 32, &bytes)
        #else
        for i in 0..<32 {
            bytes[i] = UInt8.random(in: 0...255)
        }
        #endif
        return BigInt256.fromBEBytes(bytes)
    }

    private static func kdf(keylen: Int, p2: ECPoint) -> [UInt8] {
        var result = [UInt8](repeating: 0, count: keylen)
        var ct: UInt32 = 1
        let blocks = (keylen + 31) / 32

        for i in 0..<blocks {
            let sm3 = SM3()
            _ = sm3.update(p2.x.toBEBytes())
            _ = sm3.update(p2.y.toBEBytes())
            let ctBytes = withUnsafeBytes(of: ct.bigEndian) { Array($0) }
            _ = sm3.update(ctBytes)
            _ = sm3.finalize()
            let hash = sm3.getHashBytes()

            let start = i * 32
            let end = min((i + 1) * 32, keylen)
            let copyLen = end - start
            for j in 0..<copyLen {
                result[start + j] = hash[j]
            }

            ct += 1
        }

        return result
    }

    private static func kdfKeySwap(keylen: Int, vu: ECPoint, za: [UInt8], zb: [UInt8]) -> [UInt8] {
        var result = [UInt8](repeating: 0, count: keylen)
        var ct: UInt32 = 1
        let blocks = (keylen + 31) / 32

        for i in 0..<blocks {
            let sm3 = SM3()
            _ = sm3.update(vu.x.toBEBytes())
            _ = sm3.update(vu.y.toBEBytes())
            _ = sm3.update(za)
            _ = sm3.update(zb)
            let ctBytes = withUnsafeBytes(of: ct.bigEndian) { Array($0) }
            _ = sm3.update(ctBytes)
            _ = sm3.finalize()
            let hash = sm3.getHashBytes()

            let start = i * 32
            let end = min((i + 1) * 32, keylen)
            let copyLen = end - start
            for j in 0..<copyLen {
                result[start + j] = hash[j]
            }

            ct += 1
        }

        return result
    }

    private static func userSM3Z(userId: [UInt8], publicKey: ECPoint) -> [UInt8] {
        let sm3 = SM3()

        // ENTL (2字节)
        let entl = UInt16(userId.count * 8)
        _ = sm3.update([UInt8(entl >> 8), UInt8(entl & 0xFF)])

        // ID
        _ = sm3.update(userId)

        // a
        _ = sm3.update(FpElement(SM2_A).toBEBytes())

        // b
        _ = sm3.update(FpElement(SM2_B).toBEBytes())

        // Gx
        _ = sm3.update(FpElement(SM2_GX).toBEBytes())

        // Gy
        _ = sm3.update(FpElement(SM2_GY).toBEBytes())

        // xA
        _ = sm3.update(publicKey.x.toBEBytes())

        // yA
        _ = sm3.update(publicKey.y.toBEBytes())

        _ = sm3.finalize()
        return sm3.getHashBytes()
    }

    private static func calcX(_ x: BigInt256) -> BigInt256 {
        // 2^w
        let twoPowW = BigInt256.fromHex("80000000000000000000000000000000")
        // 2^w - 1
        let mask = BigInt256.fromHex("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")
        // x & (2^w - 1)
        let xMasked = x.and(mask)
        // 2^w + masked
        let (result, _) = twoPowW.add(xMasked)
        return result
    }

    private static func calcT(n: BigInt256, r: BigInt256, d: BigInt256, x_: BigInt256) -> BigInt256 {
        let xr = x_.modMul(r, n)
        return d.modAdd(xr, n)
    }

    private static func calcPoint(t: BigInt256, x_: BigInt256, p: ECPoint, r: ECPoint) -> ECPoint {
        let xr = r.multiply(x_)
        let sum = p.add(xr)
        return sum.multiply(t)
    }

    private static func createS(tag: UInt8, vu: ECPoint, za: [UInt8], zb: [UInt8], ra: ECPoint, rb: ECPoint) -> [UInt8] {
        // 第一个哈希
        let sm3 = SM3()
        _ = sm3.update(vu.x.toBEBytes())
        _ = sm3.update(za)
        _ = sm3.update(zb)
        _ = sm3.update(ra.x.toBEBytes())
        _ = sm3.update(ra.y.toBEBytes())
        _ = sm3.update(rb.x.toBEBytes())
        _ = sm3.update(rb.y.toBEBytes())
        _ = sm3.finalize()
        let h1 = sm3.getHashBytes()

        // 第二个哈希
        let hash = SM3()
        _ = hash.update([tag])
        _ = hash.update(vu.y.toBEBytes())
        _ = hash.update(h1)
        _ = hash.finalize()
        return hash.getHashBytes()
    }
}

// MARK: - 错误类型

enum SM2Error: Error {
    case invalidInput(String)
    case invalidKey(String)
    case decryptionFailed(String)
}

// MARK: - 辅助函数

private func bytesToHex(_ bytes: [UInt8]) -> String {
    return bytes.map { String(format: "%02x", $0) }.joined()
}

private func hexToBytes(_ hex: String) throws -> [UInt8] {
    if hex.count % 2 != 0 {
        throw SM2Error.invalidInput("Invalid hex string length")
    }
    var bytes = [UInt8]()
    var index = hex.startIndex
    while index < hex.endIndex {
        let nextIndex = hex.index(index, offsetBy: 2)
        guard let byte = UInt8(hex[index..<nextIndex], radix: 16) else {
            throw SM2Error.invalidInput("Invalid hex character")
        }
        bytes.append(byte)
        index = nextIndex
    }
    return bytes
}

// MARK: - SM3扩展（获取字节数组）

extension SM3 {
    func getHashBytes() -> [UInt8] {
        let hex = getHash()
        var bytes = [UInt8]()
        var index = hex.startIndex
        while index < hex.endIndex {
            let nextIndex = hex.index(index, offsetBy: 2, limitedBy: hex.endIndex) ?? hex.endIndex
            if let byte = UInt8(hex[index..<nextIndex], radix: 16) {
                bytes.append(byte)
            }
            index = nextIndex
        }
        return bytes
    }
}

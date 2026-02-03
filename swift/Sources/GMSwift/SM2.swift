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

// MARK: - 素数域元素

public struct FpElement: Equatable {
    public var value: BigInt256

    init(_ value: BigInt256) {
        if value >= SM2_P {
            self.value = value.modSub(SM2_P, SM2_P)
        } else {
            self.value = value
        }
    }

    static func fromHex(_ hex: String) -> FpElement {
        return FpElement(BigInt256.fromHex(hex))
    }

    static let zero = FpElement(BigInt256.zero)
    static let one = FpElement(BigInt256.one)

    var isZero: Bool { return value.isZero }
    var isOne: Bool { return value.isOne }

    func add(_ other: FpElement) -> FpElement {
        return FpElement(value.modAdd(other.value, SM2_P))
    }

    func subtract(_ other: FpElement) -> FpElement {
        return FpElement(value.modSub(other.value, SM2_P))
    }

    func multiply(_ other: FpElement) -> FpElement {
        return FpElement(value.modMul(other.value, SM2_P))
    }

    func square() -> FpElement {
        return FpElement(value.modSquare(SM2_P))
    }

    func negate() -> FpElement {
        if isZero { return self }
        return FpElement(SM2_P.modSub(value, SM2_P))
    }

    func invert() -> FpElement {
        if isZero { fatalError("Cannot invert zero") }
        return FpElement(value.modInverse(SM2_P))
    }

    func divide(_ other: FpElement) -> FpElement {
        return multiply(other.invert())
    }

    func double() -> FpElement {
        return add(self)
    }

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

// MARK: - 椭圆曲线点

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

    func add(_ other: ECPoint) -> ECPoint {
        if self.infinity {
            return other
        }
        if other.infinity {
            return self
        }

        let x1 = self.x
        let y1 = self.y
        let x2 = other.x
        let y2 = other.y

        let dx = x2.subtract(x1)
        let dy = y2.subtract(y1)

        if dx.isZero {
            if dy.isZero {
                return self.twice()
            }
            return ECPoint.infinityPoint()
        }

        // lambda = (y2 - y1) / (x2 - x1)
        let lambda = dy.divide(dx)

        // x3 = lambda^2 - x1 - x2
        let x3 = lambda.square().subtract(x1).subtract(x2)

        // y3 = lambda * (x1 - x3) - y1
        let y3 = lambda.multiply(x1.subtract(x3)).subtract(y1)

        return ECPoint(x: x3, y: y3)
    }

    func twice() -> ECPoint {
        if infinity {
            return self
        }

        let y1 = self.y
        if y1.isZero {
            return ECPoint.infinityPoint()
        }

        let x1 = self.x
        let x1Sq = x1.square()

        // lambda = (3 * x1^2 + a) / (2 * y1)
        let numerator = x1Sq.triple().add(FpElement(SM2_A))
        let denominator = y1.double()
        let lambda = numerator.divide(denominator)

        // x3 = lambda^2 - 2*x1
        let x3 = lambda.square().subtract(x1.double())

        // y3 = lambda * (x1 - x3) - y1
        let y3 = lambda.multiply(x1.subtract(x3)).subtract(y1)

        return ECPoint(x: x3, y: y3)
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

        var result = ECPoint.infinityPoint()
        var addend = self
        let bitLen = k.bitLength

        for i in 0..<bitLen {
            if k.getBit(i) {
                result = result.add(addend)
            }
            addend = addend.twice()
        }

        return result
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
        let sg = ECPoint.generator().multiply(s)
        let tpa = pubPoint.multiply(t)
        let point = sg.add(tpa)

        if point.isInfinity {
            return false
        }

        // R = (e + x1) mod n
        let computedR = e.modAdd(point.x.toBigInt(), SM2_N)

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
